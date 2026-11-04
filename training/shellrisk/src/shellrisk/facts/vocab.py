"""Shell vocabulary lookup (shell_vocab_v1.csv): program [+ subcommand] -> verb, role, sensitive.

Matching (deterministic, Rust-portable): rows for the program; subcommand rows are tried against the first
positional argument, then the second (aws iam delete-user, gcloud compute instances delete); exact match
before prefix match (`delete-*`); otherwise the program's `*` row. Programs not in the vocabulary return
None and the extractor falls back to action_markers.verb_class.
"""
import csv
from functools import lru_cache
from pathlib import Path

HERE = Path(__file__).resolve().parent
VOCAB = HERE / 'shell_vocab_v1.csv'
VERBS = {'READ', 'MUTATE', 'DELETE', 'EXEC', 'NONE'}
ROLES = {'INTERP', 'NET', 'FILTER', 'NAV', 'OUTPUT', 'BUILD', 'PKG', 'VCS', 'CONTAINER', 'CLOUD', 'SERVICE', 'ADMIN',
         'FILE', 'PROCESS', 'ARCHIVE', 'CRYPTO', 'SEARCH', 'NOISE', 'OTHER'}


@lru_cache(maxsize=1)
def table(path=VOCAB):
    out = {}
    with open(path, newline='', encoding='utf-8') as f:
        for r in csv.DictReader(f):
            if r['verb'] not in VERBS or r['role'] not in ROLES:
                raise ValueError(f'bad vocab row {r}')
            out.setdefault(r['program'], {})[r['subcommand'].lower()] = (r['verb'], r['role'], r['sensitive'] == 'SENSITIVE_READ')
    return out


SEVERITY = {'DELETE': 4, 'EXEC': 3, 'MUTATE': 2, 'READ': 1, 'NONE': 0}
# Subcommands that are groups: the next positional argument is the actual action (docker image rm, gh pr merge).
_DOCKER_GROUPS = {'image', 'container', 'volume', 'network', 'system', 'builder', 'buildx', 'compose', 'context',
                  'plugin', 'node', 'service', 'stack', 'secret', 'config', 'swarm', 'machine', 'manifest', 'trust'}
GROUPS = {'docker': _DOCKER_GROUPS, 'podman': _DOCKER_GROUPS | {'pod', 'machine'}, 'nerdctl': _DOCKER_GROUPS,
          'gh': {'pr', 'issue', 'repo', 'release', 'run', 'workflow', 'secret', 'variable', 'gist', 'auth', 'cache',
                 'label', 'project', 'codespace', 'ssh-key', 'gpg-key', 'extension', 'ruleset'},
          'git': {'stash', 'remote', 'submodule', 'worktree', 'notes', 'lfs', 'bisect', 'sparse-checkout'},
          'kubectl': {'config', 'rollout', 'auth', 'certificate', 'set'},
          'helm': {'repo', 'plugin', 'registry'}, 'npm': {'cache', 'config', 'pkg'}, 'conda': {'env'},
          'terraform': {'state', 'workspace'}, 'launchctl': set(), 'netsh': {'advfirewall', 'firewall', 'wlan', 'interface'}}
CLOUD_CLIS = {'aws', 'gcloud', 'az', 'gsutil', 'oci', 'ibmcloud', 'doctl', 'scw'}


def _match(rows, w):
    if w in rows and w != '*':
        return w
    return max((k for k in rows if k.endswith('*') and len(k) > 1 and w.startswith(k[:-1])), key=len, default=None)


def lookup(program, rest):
    """(verb, role, sensitive, matched key) or None.
    The first positional argument is the subcommand. The next one counts only after a group (docker image rm)
    or, for cloud CLIs, while no action has matched yet (aws s3 rm, gcloud compute instances delete)."""
    rows = table().get(program)
    if not rows:
        return None
    pos = [w.lower() for w in rest if not w.startswith('-')]
    groups = GROUPS.get(program, set())
    depth = 4 if program in CLOUD_CLIS else 2
    hits = []
    for k, w in enumerate(pos[:depth]):
        m = _match(rows, w)
        if m:
            hits.append(m)
        if program in CLOUD_CLIS:
            if m and m not in groups and rows[m][0] != 'NONE' and k > 0:
                break
            continue
        if w not in groups:
            break
    if hits:
        key = max(hits, key=lambda h: SEVERITY[rows[h][0]])
        return rows[key] + (key,)
    return rows['*'] + ('*',) if '*' in rows else None
