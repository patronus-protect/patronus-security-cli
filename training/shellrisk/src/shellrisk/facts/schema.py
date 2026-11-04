"""patronus.facts/1 - structured, versioned action facts for one shell command.

Enum sets for operations, path access, network action/scope, data kind, parse status and dialect follow
DefenseClaw's `defenseclaw.guardrail.semantic.v1` schema (internal/guardrail/semanticpb/facts.proto,
Copyright 2026 Cisco Systems, Inc., Apache-2.0); see NOTICE. Patronus adds object classes, sinks and flow
data kinds. All values are closed enums; documents are emitted as canonical JSON (sorted keys, sorted sets).

Command = {
  "v": "1.0", "dialect": Dialect, "parse_status": ParseStatus, "context": {...} | null,
  "segments": [Segment], "flows": [Flow], "objects": [Object], "atoms": [str], "writes": [Write],
  "downloads": [str]
}
Segment = {"id", "head", "program", "verb", "ops": [OperationKind], "objects": [Object],
           "kv": [str], "settings": [Setting], "grants": [str], "container": {...}, "fixture": bool, "secctl": bool,
           "network": [{"host": str, "scope": NetworkScope}], "argv": [str]}
Object  = {"value": str, "class": ObjectClass, "access": PathAccess|null, "abs": str|null}
Setting = {"domain": "SECCTL"|"OTHER", "polarity": "ON"|"OFF"}
Flow    = {"data": FlowData, "sink": Sink, "via": Via}
Write   = {"path": str, "data": FlowData}       (secret material written to a file, for prior_facts linking)
"""
import json

VERSION = '1.0'

# DefenseClaw-derived enums (names without the OPERATION_KIND_ prefix)
OPERATION_KINDS = ['EXECUTE', 'READ', 'WRITE', 'APPEND', 'DELETE', 'COPY', 'MOVE', 'LIST', 'SEARCH', 'FETCH',
                   'UPLOAD', 'CONNECT', 'LISTEN', 'TUNNEL', 'NETWORK_SCAN', 'DECODE', 'PROCESS_KILL', 'DISK_WRITE',
                   'PRIVILEGE', 'PERMISSION_CHANGE', 'CONFIG_CHANGE', 'ACCOUNT_CHANGE', 'SCHEDULE', 'CONTAINER_RUN',
                   'WORKLOAD_EXEC', 'NAMESPACE_ENTER', 'ROOT_CHANGE', 'ENVIRONMENT_READ', 'CREDENTIAL_READ',
                   'POLICY_BYPASS']
PATH_ACCESS = ['READ', 'WRITE', 'APPEND', 'DELETE', 'EXECUTE', 'LIST', 'METADATA', 'CONNECT']
NETWORK_SCOPE = ['UNKNOWN', 'LOOPBACK', 'LINK_LOCAL', 'PRIVATE', 'PUBLIC']
DATA_KIND = ['STDIN', 'STDOUT', 'FILE', 'NETWORK', 'PROCESS']
PARSE_STATUS = ['NOT_APPLICABLE', 'COMPLETE', 'PARTIAL', 'UNSUPPORTED', 'INVALID', 'LIMIT_EXCEEDED', 'AMBIGUOUS']
DIALECT = ['NONE', 'ARGV', 'POSIX', 'POWERSHELL', 'CMD', 'MIXED']

# Patronus enums
VERBS = ['READ', 'MUTATE', 'DELETE', 'EXEC']
OBJECT_CLASSES = ['ROOT', 'SYSTEM', 'SECRET', 'PERSIST', 'GIT_EXEC_CONFIG', 'SERVICE', 'TMP', 'HOME', 'PROJECT',
                  'FIXTURE']
FLOW_DATA = ['REMOTE', 'SECRET', 'PUBLIC_KEY', 'LITERAL', 'PROJECT', 'OTHER', 'DECODED', 'CRED_LITERAL', 'DB_DUMP']
SINKS = ['INTERP', 'EXEC', 'FILE', 'FILTER', 'NET']
VIAS = ['PIPE', 'SUBST', 'SAME_PATH', 'ARG', 'UPLOAD', 'REDIRECT', 'PRIOR_PATH']


def _sort_key(x):
    return json.dumps(x, sort_keys=True)


def canonical(obj):
    """Canonical form: dict keys sorted (by json.dumps), every list of scalars or dicts sorted, except
    `segments`, whose order is the command order."""
    if isinstance(obj, dict):
        return {k: (canonical(v) if k != 'segments' else [canonical(s) for s in v]) for k, v in obj.items()}
    if isinstance(obj, list):
        return sorted((canonical(v) for v in obj), key=_sort_key)
    return obj


def dumps(facts):
    return json.dumps(canonical(facts), sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def validate(facts):
    """Light structural validation against the closed enums; raises ValueError."""
    def need(cond, msg):
        if not cond:
            raise ValueError(msg)
    need(facts.get('v') == VERSION, 'version')
    need(facts['dialect'] in DIALECT, 'dialect')
    need(facts['parse_status'] in PARSE_STATUS, 'parse_status')
    for s in facts['segments']:
        need(s['verb'] in VERBS + [None], f"verb {s['verb']}")
        need(all(o in OPERATION_KINDS for o in s['ops']), f"ops {s['ops']}")
        for o in s['objects']:
            need(o['class'] in OBJECT_CLASSES, f"class {o['class']}")
            need(o['access'] in PATH_ACCESS + [None], f"access {o['access']}")
        for n in s.get('network', []):
            need(n['scope'] in NETWORK_SCOPE, f"scope {n['scope']}")
    for f in facts['flows']:
        need(f['data'] in FLOW_DATA and f['sink'] in SINKS and f['via'] in VIAS, f'flow {f}')
    for o in facts['objects']:
        need(o['class'] in OBJECT_CLASSES, f"class {o['class']}")
    return True
