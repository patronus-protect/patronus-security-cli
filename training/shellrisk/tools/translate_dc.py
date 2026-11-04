"""Provenance script (see tools/README.md): ran in the research workspace; paths below are the original ones.

Translate DefenseClaw default rule packs (Apache-2.0) into Cedar conditions over our segment facts.

Supported CEL subset (everything else is skipped with a reason):
  f.tool == 'x' | f.tool in [...]                constant-folded for a shell tool call
  f.commands.exists(c, E)                        E over one segment; OR of several exists is fine
  c.argv_complete                                always true for us
  c.program == 'x' | c.program in [...]
  <...>.OPERATION_KIND_X in c.operations         X must be one of facts.OPS
  &&  ||  ( )  true  false
The regex `pattern` (Go RE2) becomes a named pattern matched on the whole command text; 'a^'
means "no pattern". Severity caps: CRITICAL/HIGH -> block, MEDIUM -> ask, LOW -> skipped.
Rules are bucketed by rule_id exactly like run H (test rules are the held-out half).
Output: h/rules/translated.json
Run: Patronus-Datasets/.venv/bin/python -I h/translate_dc.py
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from facts import OPS  # noqa: E402

PACKS = HERE.parent / 'raw' / 'defenseclaw' / 'policies' / 'guardrail' / 'default' / 'rules'
SHELL_TOOLS = {'shell', 'bash', 'sh', 'zsh', 'run_shell', 'exec', 'exec_command', 'execute_command', 'terminal',
               'run_command', 'run_terminal_cmd', 'powershell', 'pwsh', 'cmd', 'command'}
TOKEN = re.compile(r"\s*(?:(\|\||&&|==|!=|[()\[\],!])|('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")|([A-Za-z_][\w.]*))")


class Unsupported(Exception):
    pass


def lex(s):
    pos, out = 0, []
    while pos < len(s):
        if s[pos:].strip() == '':
            break
        m = TOKEN.match(s, pos)
        if not m:
            raise Unsupported(f'lex at {s[pos:pos + 20]!r}')
        op, st, ident = m.groups()
        out.append(('op', op) if op else ('str', st[1:-1]) if st else ('id', ident))
        pos = m.end()
    return out


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k] if self.i + k < len(self.t) else (None, None)

    def take(self, kind=None, val=None):
        tok = self.peek()
        if (kind and tok[0] != kind) or (val and tok[1] != val):
            raise Unsupported(f'expected {val or kind}, got {tok}')
        self.i += 1
        return tok

    def parse(self):
        node = self.or_()
        if self.i != len(self.t):
            raise Unsupported(f'trailing {self.peek()}')
        return node

    def or_(self):
        node = self.and_()
        while self.peek() == ('op', '||'):
            self.take(); node = ('or', node, self.and_())
        return node

    def and_(self):
        node = self.unary()
        while self.peek() == ('op', '&&'):
            self.take(); node = ('and', node, self.unary())
        return node

    def unary(self):
        if self.peek() == ('op', '!'):
            self.take(); return ('not', self.unary())
        if self.peek() == ('op', '('):
            self.take(); node = self.or_(); self.take('op', ')'); return node
        return self.atom()

    def strlist(self):
        self.take('op', '['); items = []
        while self.peek() != ('op', ']'):
            items.append(self.take('str')[1])
            if self.peek() == ('op', ','):
                self.take()
        self.take('op', ']')
        return items

    def atom(self):
        kind, val = self.take('id')
        if val in ('true', 'false'):
            return ('const', val == 'true')
        if val == 'f.commands.exists':
            self.take('op', '('); var = self.take('id')[1]; self.take('op', ',')
            inner = self.or_(); self.take('op', ')')
            return ('exists', var, inner)
        if val in ('f.tool', 'c.program'):
            nxt = self.take()
            if nxt == ('op', '=='):
                lit = [self.take('str')[1]]
            elif nxt == ('id', 'in'):
                lit = self.strlist()
            else:
                raise Unsupported(f'{val} with {nxt}')
            return ('tool', lit) if val == 'f.tool' else ('prog', [x.lower() for x in lit])
        if val == 'c.argv_complete':
            return ('const', True)
        if val.split('.')[-1].startswith('OPERATION_KIND_'):
            self.take('id', 'in'); target = self.take('id')[1]
            if target != 'c.operations':
                raise Unsupported(f'op in {target}')
            kind_name = val.split('.')[-1][len('OPERATION_KIND_'):]
            if kind_name not in OPS:
                raise Unsupported(f'operation kind {kind_name}')
            return ('op', kind_name)
        raise Unsupported(f'field {val}')


def fold(n):
    t = n[0]
    if t == 'tool':
        return ('const', any(x in SHELL_TOOLS for x in n[1]))
    if t in ('and', 'or'):
        a, b = fold(n[1]), fold(n[2])
        if a[0] == 'const':
            return (b if a[1] else a) if t == 'and' else (a if a[1] else b)
        if b[0] == 'const':
            return (a if b[1] else b) if t == 'and' else (b if b[1] else a)
        return (t, a, b)
    if t == 'not':
        a = fold(n[1])
        return ('const', not a[1]) if a[0] == 'const' else ('not', a)
    if t == 'exists':
        inner = fold(n[2])
        return ('const', False) if inner == ('const', False) else ('exists', n[1], inner)
    return n


def segment_cedar(n):
    """Cedar condition for a folded node evaluated on one segment request."""
    t = n[0]
    if t == 'const':
        return 'true' if n[1] else 'false'
    if t == 'exists':
        return segment_cedar(n[2])
    if t == 'or':
        return f'({segment_cedar(n[1])} || {segment_cedar(n[2])})'
    if t == 'and':
        if count_exists(n[1]) and count_exists(n[2]):
            raise Unsupported('AND of two commands.exists (needs cross-segment binding)')
        return f'({segment_cedar(n[1])} && {segment_cedar(n[2])})'
    if t == 'not':
        if count_exists(n[1]):
            raise Unsupported('NOT over commands.exists')
        return f'!({segment_cedar(n[1])})'
    if t == 'prog':
        return '[' + ', '.join(json.dumps(x) for x in n[1]) + '].contains(context.program)'
    if t == 'op':
        return f'context.ops.contains({json.dumps(n[1])})'
    raise Unsupported(f'node {t}')


def count_exists(n):
    return (n[0] == 'exists') + sum(count_exists(c) for c in n[1:] if isinstance(c, tuple))


def bucket(key, fit=60, val=15):
    import hashlib
    h = int(hashlib.sha256(('run-h:' + key).encode()).hexdigest(), 16) % 100
    return 'fit' if h < fit else 'val' if h < fit + val else 'test'


def main():
    out, reasons = [], Counter()
    for f in sorted(PACKS.glob('*.yaml')):
        if f.stem == 'trust-exploit':
            continue  # prompt-injection / trust patterns in tool args: not shell risk, not in this bundle
        for r in yaml.safe_load(f.read_text())['rules']:
            if r['id'].startswith('TRUST-'):
                continue
            rec = {'id': r['id'], 'pack': f.stem, 'severity': r['severity'], 'confidence': r.get('confidence'),
                   'title': r.get('title'), 'bucket': bucket('dc/' + r['id'])}
            try:
                if r['severity'] == 'LOW':
                    raise Unsupported('severity LOW not adopted')
                rec['cap'] = 'ask' if r['severity'] == 'MEDIUM' else 'block'
                pattern = r.get('pattern')
                pattern = None if pattern in (None, '', 'a^') else pattern
                if pattern is not None:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        raise Unsupported(f'regex not portable: {e}')
                expr = ' '.join((r.get('expression') or '').split())
                cond = 'true'
                if expr:
                    node = fold(Parser(lex(expr)).parse())
                    if node == ('const', False):
                        raise Unsupported('expression folds to false for shell tool calls')
                    cond = segment_cedar(node)
                if pattern is None and cond == 'true':
                    raise Unsupported('neither pattern nor usable expression')
                if pattern is None and 'context.ops.contains' not in cond:
                    # Expression only scopes the rule (e.g. "applies to psql/mysql"); with the never-matching
                    # pattern 'a^' the detection lives in a DefenseClaw-specific analyzer we do not have.
                    raise Unsupported('scope-only expression, detection by external analyzer')
                rec.update(status='translated', pattern=pattern, condition=cond)
            except Unsupported as e:
                rec.update(status='skipped', reason=str(e))
                reasons[re.sub(r"[:].*|'.*", '', str(e))[:60]] += 1
            out.append(rec)
    dest = HERE / 'rules'; dest.mkdir(exist_ok=True)
    (dest / 'translated.json').write_text(json.dumps(out, indent=1))
    ok = [r for r in out if r['status'] == 'translated']
    print(json.dumps({'rules': len(out), 'translated': len(ok),
                      'translated_by_bucket': dict(Counter(r['bucket'] for r in ok)),
                      'translated_by_cap': dict(Counter(r['cap'] for r in ok)),
                      'with_pattern': sum(r['pattern'] is not None for r in ok),
                      'skipped_reasons': dict(reasons.most_common())}, indent=1))


if __name__ == '__main__':
    main()
