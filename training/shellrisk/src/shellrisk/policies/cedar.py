"""Cedar layer over patronus.facts/1: schema, requests, policy member.

Per command: one `segment` request per segment plus one `command` request. Policies are scoped by action
(`forbid(principal, action == Action::"command", resource) when {...}`), so every condition is checked
against the schema below; user policies are validated the same way.

Set encodings (Cedar has no regex and no quantifiers, so pairs are pre-joined):
  segment.objects   "<ACCESS>@<CLASS>"           e.g. "WRITE@PERSIST"
  segment.paths     "<ACCESS>:<normalized path>"  e.g. "READ:/etc/shadow", "READ:HKLM/SAM"
  segment.settings  "<DOMAIN>:<POLARITY>"         e.g. "SECCTL:OFF"
  command.flows     "<DATA>><SINK>" and "<DATA>><SINK>><VIA>"   e.g. "SECRET>NET", "REMOTE>EXEC>PRIOR_PATH"
  command.objects   classes named by whole-command facts (PERSIST, SECRET, GIT_EXEC_CONFIG)
"""
import json
import re

import cedarpy

from ..facts.extract import extract

SCHEMA = '''
entity Agent;
entity Target;
type SegmentContext = {
  program: String, verb: String, role: String, sensitive_read: Bool, nested: String, sql: Set<String>, ops: Set<String>, access: Set<String>, classes: Set<String>,
  objects: Set<String>, paths: Set<String>, values: Set<String>, argv: Set<String>, settings: Set<String>,
  grants: Set<String>, host_root_mount: Bool, privileged: Bool, fixture: Bool, hosts: Set<String>,
  net_scopes: Set<String>, dialect: String, patterns: Set<String>
};
type CommandContext = {
  flows: Set<String>, objects: Set<String>, atoms: Set<String>, programs: Set<String>, ops: Set<String>,
  settings: Set<String>, hosts: Set<String>, net_scopes: Set<String>, dialect: String, segments: Long,
  patterns: Set<String>
};
action segment appliesTo { principal: Agent, resource: Target, context: SegmentContext };
action command appliesTo { principal: Agent, resource: Target, context: CommandContext };
'''
BASE = '@id("base") permit(principal, action, resource);'
REQ = {'principal': 'Agent::"shell"', 'resource': 'Target::"command"'}


def norm_path(p):
    """DefenseClaw-style normalized path: forward slashes, registry roots shortened (HKLM/SAM)."""
    p = p.replace('\\', '/')
    p = re.sub(r'^(HKEY_LOCAL_MACHINE|HKLM:?)(/|$)', r'HKLM\2', p, flags=re.I)
    p = re.sub(r'^(HKEY_CURRENT_USER|HKCU:?)(/|$)', r'HKCU\2', p, flags=re.I)
    return re.sub(r'/+', '/', p)


def requests(facts, patterns=()):
    pats = sorted(patterns)
    segs = []
    for s in facts['segments']:
        values = set()
        paths, objs = set(), set()
        for o in s['objects']:
            vs = {norm_path(o['value'])} | ({o['abs']} if o['abs'] else set())
            values |= vs
            if o['access']:
                paths |= {f"{o['access']}:{v}" for v in vs}
                objs.add(f"{o['access']}@{o['class']}")
        segs.append({**REQ, 'action': 'Action::"segment"', 'context': {
            'program': s['program'], 'verb': s['verb'] or '', 'role': s.get('role') or '',
            'sensitive_read': bool(s.get('sensitive')), 'nested': s.get('nested') or '', 'sql': s.get('sql', []),
            'ops': s['ops'],
            'access': sorted({o['access'] for o in s['objects'] if o['access']}),
            'classes': sorted({o['class'] for o in s['objects']}), 'objects': sorted(objs), 'paths': sorted(paths),
            'values': sorted(values), 'argv': sorted(set(s['argv'])),
            'settings': sorted({f"{x['domain']}:{x['polarity']}" for x in s['settings']}),
            'grants': s['grants'], 'host_root_mount': s['container']['host_root_mount'],
            'privileged': s['container']['privileged'], 'fixture': s['fixture'],
            'hosts': sorted({n['host'] for n in s['network']}), 'net_scopes': sorted({n['scope'] for n in s['network']}),
            'dialect': facts['dialect'], 'patterns': pats}})
    flows = set()
    for f in facts['flows']:
        flows |= {f"{f['data']}>{f['sink']}", f"{f['data']}>{f['sink']}>{f['via']}"}
    cmd = {**REQ, 'action': 'Action::"command"', 'context': {
        'flows': sorted(flows), 'objects': sorted({o['class'] for o in facts['objects']}), 'atoms': facts['atoms'],
        'programs': sorted({s['program'] for s in facts['segments']}),
        'ops': sorted({o for s in facts['segments'] for o in s['ops']}),
        'settings': sorted({f"{x['domain']}:{x['polarity']}" for s in facts['segments'] for x in s['settings']}),
        'hosts': sorted({n['host'] for s in facts['segments'] for n in s['network']}),
        'net_scopes': sorted({n['scope'] for s in facts['segments'] for n in s['network']}),
        'dialect': facts['dialect'], 'segments': len(facts['segments']), 'patterns': pats}}
    return segs + [cmd]


def policy_text(rules):
    parts = [BASE]
    for i, r in enumerate(rules):
        cond = r['condition']
        if r.get('pattern'):
            cond = f'({cond}) && context.patterns.contains("p{i}")'
        parts.append(f'@id({json.dumps(r["id"])}) forbid(principal, action == Action::"{r.get("scope", "segment")}", '
                     f'resource) when {{ {cond} }};')
    return '\n'.join(parts)


def validate(rules):
    res = cedarpy.validate_policies(policy_text(rules), SCHEMA)
    return res.validation_passed, [str(e) for e in res.errors]


class FactsMember:
    """Policy matcher on patronus.facts/1 requests: hits(texts) -> [set of fired policy ids] per text."""

    def __init__(self, rules, mode='fixed', context=None):
        self.rules, self.mode, self.context = rules, mode, context
        self.patterns = [(f'p{i}', re.compile(r['pattern'])) for i, r in enumerate(rules) if r.get('pattern')]
        self.policy_text = policy_text(rules)
        ok, errs = validate(rules)
        if not ok:
            raise ValueError(f'policies fail schema validation: {errs[:3]}')
        self.cache = {}

    def hits(self, texts):
        todo = [t for t in dict.fromkeys(texts) if t not in self.cache]
        reqs, owner = [], []
        for t in todo:
            hit = {pid for pid, rx in self.patterns if rx.search(t)}
            rq = requests(extract(t, context=self.context, mode=self.mode), hit)
            reqs += rq; owner += [t] * len(rq)
            self.cache[t] = set()
        for start in range(0, len(reqs), 4000):
            chunk = reqs[start:start + 4000]
            for t, res in zip(owner[start:start + 4000], cedarpy.is_authorized_batch(chunk, self.policy_text, [])):
                if res.diagnostics.errors:
                    raise RuntimeError(res.diagnostics.errors[:2])
                for pid in res.diagnostics.reasons:
                    k = int(pid.replace('policy', ''))
                    if k > 0:
                        self.cache[t].add(self.rules[k - 1]['id'])
        return [self.cache[t] for t in texts]
