"""Provenance script (see tools/README.md): ran in the research workspace; paths below are the original ones.

Translate DefenseClaw default rule packs (Apache-2.0) to Cedar over patronus.facts/1 (f/cedar_facts.py).

Extends h/translate_dc.py (same CEL subset, same severity caps and rule buckets) with:
  f.paths.exists(p, ...)     p.access == / in, p.normalized == / in, p.command_id == c.id, p.flavor (ignored)
                             -> segment `paths` (access + path together), `access` or `values`
  f.network.exists(n, ...)   n.action == / in  -> segment ops (DOWNLOAD->FETCH, CONNECT, UPLOAD, LISTEN, SCAN),
                             n.scope == / in   -> segment net_scopes, n.command_id == c.id
  'x' in c.argv              -> segment argv
  c.program != 'x'
  OPERATION_KIND_APPEND      -> WRITE (we do not split WRITE/APPEND on segment ops)
  OPERATION_KIND_POLICY_BYPASS -> setting SECCTL:OFF (approximation of DefenseClaw's bypass analyzer)
Every translation is checked against the Cedar schema. Approximations are listed per rule.
Output: f/rules/dc_facts.json
Run: Patronus-Datasets/.venv/bin/python -I f/translate_dc_facts.py
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path[:0] = [str(HERE), str(ROOT / 'h')]
import translate_dc as tdc  # noqa: E402
from cedar_facts import validate  # noqa: E402
from schema import OPERATION_KINDS  # noqa: E402

NET_ACTION_OPS = {'DOWNLOAD': 'FETCH', 'CONNECT': 'CONNECT', 'UPLOAD': 'UPLOAD', 'LISTEN': 'LISTEN',
                  'SCAN': 'NETWORK_SCAN', 'FETCH': 'FETCH'}
PRODUCED_OPS = {'READ', 'DELETE', 'CONFIG_CHANGE', 'EXECUTE', 'PERMISSION_CHANGE', 'CREDENTIAL_READ', 'FETCH',
                'DECODE', 'LISTEN', 'CONNECT', 'WRITE', 'PRIVILEGE', 'UPLOAD', 'DISK_WRITE', 'COPY', 'CONTAINER_RUN',
                'PROCESS_KILL', 'ACCOUNT_CHANGE', 'NETWORK_SCAN'}


def enum_tail(ident, prefix):
    tail = ident.split('.')[-1]
    if not tail.startswith(prefix):
        raise tdc.Unsupported(f'{ident} is not {prefix}*')
    return tail[len(prefix):]


class Parser(tdc.Parser):
    def __init__(self, toks):
        super().__init__(toks)
        self.approx = []

    def identlist(self):
        self.take('op', '['); items = []
        while self.peek() != ('op', ']'):
            items.append(self.take('id')[1])
            if self.peek() == ('op', ','):
                self.take()
        self.take('op', ']')
        return items

    def enum_values(self, prefix):
        nxt = self.take()
        if nxt == ('op', '=='):
            return [enum_tail(self.take('id')[1], prefix)]
        if nxt == ('id', 'in'):
            return [enum_tail(x, prefix) for x in self.identlist()]
        raise tdc.Unsupported(f'enum compare {nxt}')

    def str_values(self):
        nxt = self.take()
        if nxt == ('op', '=='):
            return [self.take('str')[1]]
        if nxt == ('id', 'in'):
            return self.strlist()
        raise tdc.Unsupported(f'string compare {nxt}')

    def unary(self):
        if self.peek()[0] == 'str':  # 'x' in c.argv
            lit = self.take('str')[1]; self.take('id', 'in'); target = self.take('id')[1]
            if target != 'c.argv':
                raise tdc.Unsupported(f'str in {target}')
            return ('argv', lit.lower())
        return super().unary()

    def atom(self):
        kind, val = self.peek()
        if val in ('f.paths.exists', 'f.network.exists'):
            self.take(); self.take('op', '('); self.take('id'); self.take('op', ',')
            inner = self.or_(); self.take('op', ')')
            return ('pexists' if val == 'f.paths.exists' else 'nexists', inner)
        if val in ('p.command_id', 'n.command_id'):
            self.take(); self.take('op', '=='); self.take('id', 'c.id')
            return ('const', True)
        if val == 'p.access':
            self.take(); return ('p.access', self.enum_values('PATH_ACCESS_'))
        if val == 'p.normalized':
            self.take(); return ('p.value', self.str_values())
        if val == 'p.normalized.startsWith':
            raise tdc.Unsupported('path prefix (startsWith) not expressible on Cedar sets')
        if val == 'p.flavor':
            self.take(); self.enum_values('PATH_FLAVOR_'); self.approx.append('path flavor ignored')
            return ('const', True)
        if val == 'n.action':
            self.take(); return ('n.action', self.enum_values('NETWORK_ACTION_'))
        if val == 'n.scope':
            self.take(); return ('n.scope', self.enum_values('NETWORK_SCOPE_'))
        if val == 'c.program' and self.peek(1) == ('op', '!='):
            self.take(); self.take(); return ('not', ('prog', [self.take('str')[1].lower()]))
        if val.split('.')[-1].startswith('OPERATION_KIND_'):
            self.take(); self.take('id', 'in'); target = self.take('id')[1]
            if target != 'c.operations':
                raise tdc.Unsupported(f'op in {target}')
            k = val.split('.')[-1][len('OPERATION_KIND_'):]
            if k not in OPERATION_KINDS:
                raise tdc.Unsupported(f'operation kind {k}')
            if k == 'APPEND':
                self.approx.append('APPEND op as WRITE'); return ('op', 'WRITE')
            if k == 'POLICY_BYPASS':
                self.approx.append('POLICY_BYPASS as SECCTL:OFF'); return ('bypass',)
            if k not in PRODUCED_OPS:
                raise tdc.Unsupported(f'operation kind {k} not produced by the extractor')
            return ('op', k)
        return super().atom()


def conj(n):
    """Flatten an AND-only tree into atoms; OR inside a path/network existential is unsupported."""
    if n[0] == 'and':
        return conj(n[1]) + conj(n[2])
    if n[0] in ('or', 'not'):
        raise tdc.Unsupported(f'{n[0]} inside paths/network exists')
    return [n]


def fold(n):
    t = n[0]
    if t in ('pexists', 'nexists'):
        return (t, fold(n[1]))
    if t in ('and', 'or'):
        a, b = fold(n[1]), fold(n[2])
        if a[0] == 'const':
            return (b if a[1] else a) if t == 'and' else (a if a[1] else b)
        if b[0] == 'const':
            return (a if b[1] else b) if t == 'and' else (b if b[1] else a)
        return (t, a, b)
    if t == 'not':
        a = fold(n[1]); return ('const', not a[1]) if a[0] == 'const' else ('not', a)
    if t == 'exists':
        inner = fold(n[2]); return ('const', False) if inner == ('const', False) else ('exists', n[1], inner)
    if t == 'tool':
        return ('const', any(x in tdc.SHELL_TOOLS for x in n[1]))
    return n


def cset(xs):
    return '[' + ', '.join(json.dumps(x) for x in sorted(set(xs))) + ']'


def count_exists(n):
    return (n[0] in ('exists', 'pexists', 'nexists')) + sum(count_exists(c) for c in n[1:] if isinstance(c, tuple))


def cedar(n):
    t = n[0]
    if t == 'const':
        return 'true' if n[1] else 'false'
    if t == 'exists':
        return cedar(n[2])
    if t == 'or':
        return f'({cedar(n[1])} || {cedar(n[2])})'
    if t == 'and':
        if n[1][0] == 'exists' and n[2][0] == 'exists':
            raise tdc.Unsupported('AND of two commands.exists (needs cross-segment binding)')
        if n[1][0] == 'pexists' and n[2][0] == 'pexists' and n[1] != n[2]:
            raise tdc.Unsupported('AND of two paths.exists (two objects, maybe in different segments)')
        return f'({cedar(n[1])} && {cedar(n[2])})'
    if t == 'not':
        if count_exists(n[1]):
            raise tdc.Unsupported('NOT over exists')
        return f'!({cedar(n[1])})'
    if t == 'prog':
        return f'{cset(n[1])}.contains(context.program)'
    if t == 'op':
        return f'context.ops.contains({json.dumps(n[1])})'
    if t == 'bypass':
        return 'context.settings.contains("SECCTL:OFF")'
    if t == 'argv':
        return f'context.argv.contains({json.dumps(n[1])})'
    if t == 'pexists':
        acc, vals = None, None
        for a in conj(n[1]):
            if a[0] == 'p.access':
                acc = a[1]
            elif a[0] == 'p.value':
                vals = a[1]
            elif a != ('const', True):
                raise tdc.Unsupported(f'path predicate {a[0]}')
        if acc and vals:
            return f'context.paths.containsAny({cset(f"{x}:{v}" for x in acc for v in vals)})'
        if acc:
            return f'context.access.containsAny({cset(acc)})'
        if vals:
            return f'context.values.containsAny({cset(vals)})'
        return 'true'
    if t == 'nexists':
        parts = []
        for a in conj(n[1]):
            if a[0] == 'n.action':
                parts.append(f'context.ops.containsAny({cset(NET_ACTION_OPS[x] for x in a[1])})')
            elif a[0] == 'n.scope':
                parts.append(f'context.net_scopes.containsAny({cset(a[1])})')
            elif a != ('const', True):
                raise tdc.Unsupported(f'network predicate {a[0]}')
        return '(' + ' && '.join(parts) + ')' if parts else 'true'
    raise tdc.Unsupported(f'node {t}')


# Rules whose expression lacks the predicate their title promises: the detection lives in DefenseClaw's analyzer.
NOT_EXPRESSED = {'exfil.credential_file_external_upload':
                 'expression is any public upload; the credential-file predicate lives in the external analyzer '
                 '(covered by core.secret_to_net)'}
DETECTING = re.compile(r'context\.(ops|paths|access|values|net_scopes|settings|argv)\.')


def main():
    out, reasons = [], Counter()
    for f in sorted(tdc.PACKS.glob('*.yaml')):
        if f.stem == 'trust-exploit':
            continue
        for r in yaml.safe_load(f.read_text())['rules']:
            if r['id'].startswith('TRUST-'):
                continue
            rec = {'id': r['id'], 'pack': f.stem, 'severity': r['severity'], 'title': r.get('title'),
                   'bucket': tdc.bucket('dc/' + r['id']), 'scope': 'segment', 'tier': 'bundle-default'}
            try:
                if r['id'] in NOT_EXPRESSED:
                    raise tdc.Unsupported(NOT_EXPRESSED[r['id']])
                if r['severity'] == 'LOW':
                    raise tdc.Unsupported('severity LOW not adopted')
                rec['cap'] = 'ask' if r['severity'] == 'MEDIUM' else 'block'
                pattern = r.get('pattern')
                pattern = None if pattern in (None, '', 'a^') else pattern
                if pattern is not None:
                    try:
                        re.compile(pattern)
                    except re.error as e:
                        raise tdc.Unsupported(f'regex not portable: {e}')
                expr = ' '.join((r.get('expression') or '').split())
                cond, approx = 'true', []
                if expr:
                    p = Parser(tdc.lex(expr))
                    node = fold(p.parse())
                    if node == ('const', False):
                        raise tdc.Unsupported('expression folds to false for shell tool calls')
                    cond, approx = cedar(node), p.approx
                if pattern is None and not DETECTING.search(cond):
                    raise tdc.Unsupported('scope-only expression, detection by external analyzer'
                                          if expr else 'neither pattern nor usable expression')
                if cond == 'true':
                    rec['scope'] = 'command'  # regex-only: the command request exists even when no segment parses
                rec.update(status='translated', pattern=pattern, condition=cond, approx=sorted(set(approx)))
                ok, errs = validate([rec])
                if not ok:
                    raise tdc.Unsupported(f'schema: {errs[0][:80]}')
            except tdc.Unsupported as e:
                rec.update(status='skipped', reason=str(e))
                reasons[re.sub(r"[:].*|'.*", '', str(e))[:70]] += 1
            out.append(rec)
    dest = HERE / 'rules'; dest.mkdir(exist_ok=True)
    (dest / 'dc_facts.json').write_text(json.dumps(out, indent=1))
    old = {r['id']: r['status'] for r in json.loads((ROOT / 'h' / 'rules' / 'translated.json').read_text())}
    ok = [r for r in out if r['status'] == 'translated']
    print(json.dumps({'rules': len(out), 'translated': len(ok), 'translated_before': sum(v == 'translated' for v in old.values()),
                      'newly_translated': sorted(r['id'] for r in ok if old.get(r['id']) != 'translated'),
                      'lost': sorted(r['id'] for r in out if r['status'] != 'translated' and old.get(r['id']) == 'translated'),
                      'fact_only (no regex)': sum(r['pattern'] is None for r in ok),
                      'with_approx': sum(bool(r['approx']) for r in ok),
                      'skipped_reasons': dict(reasons.most_common())}, indent=1))


if __name__ == '__main__':
    main()
