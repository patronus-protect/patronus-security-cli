"""Token-block features of the shell-risk model; kf1 = live tokens + legacy markers + fact tokens. Deterministic and Rust-portable; text is never executed.

kv1 = live tokenizer (g) + abstract semantic markers:
  TURNS_ON / TURNS_OFF            polarity of a setting change: key polarity (enable/allow/use/... vs
                                  disable/deny/block/exclude...) x value polarity (1/true/on/... vs 0/false/off/...),
                                  or an on/off verb (start/enable vs stop/disable/uninstall/unload/flush)
  SECCTL                          an argument names a security control (audit, defender, amsi, edr, firewall, ...)
  TURNS_OFF@SECCTL, TURNS_ON@SECCTL
  GRANT_ALL / GRANT_SCOPED        sudoers-style NOPASSWD: ALL vs a scoped command
  HOST_ROOT_MOUNT, PRIVILEGED     container host-root bind mount, --privileged(=true)
  TGT=FIXTURE                     path under testdata/fixtures/examples/samples (fixture, not a real secret)
Markers are de-duplicated and sorted, appended after the live features.
"""
import functools
import re

from .markers import head_and_rest, segments
from .tokens import features as g_features

NEG_KEY = re.compile(r'(disable|deny|block|exclu|skip|bypass|nocheck|^no[A-Z_]|^no-|ignore|allowunsigned)', re.I)
POS_KEY = re.compile(r'(enable|allow|^use|start|active|protect|enforce|audit|log|monitor|scan|firewall|guard|'
                     r'realtime|consent|lua|amsi|etw|selinux|apparmor|defender)', re.I)
ON_VAL = {'1', 'true', '$true', 'yes', 'on', 'enable', 'enabled', 'start', 'allow', 'enforcing', 'active'}
OFF_VAL = {'0', 'false', '$false', 'no', 'off', 'disable', 'disabled', 'stop', 'deny', 'none', 'permissive',
           'inactive'}
ON_VERBS = {'start', 'enable', 'unmask', 'load', 'install', 'restore'}
OFF_VERBS = {'stop', 'disable', 'mask', 'unload', 'uninstall', 'remove', 'kill', 'flush', 'clear', 'delete',
             'deletejournal', 'erase', 'purge', 'reset'}
SECCTL = re.compile(r'(audit|defender|windefend|mpsvc|sense|amsi|etw|eventlog|autologger|sysmon|falcon|crowdstrike|'
                    r'carbonblack|cbdefense|sentinel|mdatp|edr|xdr|antivirus|antispyware|realtime|firewall|ufw|'
                    r'firewalld|iptables|nftables|\bpf\b|selinux|apparmor|setenforce|wdigest|lsa|credentialguard|'
                    r'uac|enablelua|consentprompt|cloudtrail|flow-logs|flowlog|guardduty|securityhub|syslog|journald|'
                    r'rsyslog|osquery|wazuh|ossec|tamper|usn|smartscreen|applocker|wdac|bitlocker|aslr|randomize_va)', re.I)
FIXTURE = re.compile(r'(^|[/\\])(testdata|test-data|fixtures?|examples?|samples?|__fixtures__|mocks?)([/\\]|$)', re.I)


def polarity_value(v):
    v = v.strip('\'"').lower()
    return 'ON' if v in ON_VAL else 'OFF' if v in OFF_VAL else None


def turns(key, value):
    pv = polarity_value(value)
    if pv is None:
        return None
    if NEG_KEY.search(key):
        return 'TURNS_OFF' if pv == 'ON' else 'TURNS_ON'
    if POS_KEY.search(key):
        return 'TURNS_ON' if pv == 'ON' else 'TURNS_OFF'
    return None


def segment_markers(head, rest):
    out = set()
    words = [head] + rest
    joined = ' '.join(words)
    if SECCTL.search(joined):
        out.add('SECCTL')
    # key/value pairs: /v NAME ... /d VAL (reg), -Name N -Value V, -Flag VAL, key=value, --value V
    name = None
    for k, w in enumerate(rest):
        lw = w.lower()
        nxt = rest[k + 1] if k + 1 < len(rest) else ''
        if lw in ('/v', '-name', '-valuename') and nxt:
            name = nxt
        elif lw in ('/d', '-value', '--value', '-data') and nxt:
            t = turns(name, nxt) if name else None
            if t is None and lw == '--value':
                pv = polarity_value(nxt)
                t = {'ON': 'TURNS_ON', 'OFF': 'TURNS_OFF'}.get(pv)
            if t:
                out.add(t)
        elif lw.startswith('-') and len(lw) > 2 and nxt and polarity_value(nxt) and not nxt.startswith('-'):
            t = turns(w.lstrip('-'), nxt)
            if t:
                out.add(t)
        m = re.match(r'^-{0,2}([A-Za-z_][\w.-]{1,60})[:=](.+)$', w)
        if m:
            t = turns(m.group(1), m.group(2))
            if t:
                out.add(t)
    if head in ('setenforce',) and rest:
        out.add('TURNS_ON' if rest[0].lower() in ('1', 'enforcing') else 'TURNS_OFF')
    if head in ('auditctl',) and '-e' in rest:
        v = rest[rest.index('-e') + 1] if rest.index('-e') + 1 < len(rest) else ''
        out.add('TURNS_ON' if v == '1' else 'TURNS_OFF' if v == '0' else '')
    verbs = [w.lower() for w in rest[:3] if not w.startswith('-')]
    if head in ('systemctl', 'service', 'sc', 'launchctl', 'ufw', 'sysmon', 'netsh', 'fsutil', 'auditpol',
                'mdatp', 'wevtutil', 'aws', 'gcloud', 'az') or head.endswith('-service'):
        if any(v in OFF_VERBS or v.startswith(('stop', 'disable', 'delete', 'remove', 'clear')) for v in verbs) \
                or any(w.lower() in ('-u', '/clear', 'disable', 'stop', '/success:disable', '/failure:disable')
                       or w.lower().endswith((':disable', '=disabled')) for w in rest):
            out.add('TURNS_OFF')
        elif any(v in ON_VERBS or v.startswith(('start', 'enable')) for v in verbs) or '-i' in rest:
            out.add('TURNS_ON')
    if head.startswith(('stop-service', 'set-service', 'disable-', 'uninstall-', 'remove-')):
        out.add('TURNS_OFF')
    if head.startswith(('start-service', 'enable-', 'install-')):
        out.add('TURNS_ON')
    if out & {'TURNS_ON', 'TURNS_OFF'} and 'SECCTL' in out:
        out |= {f'{t}@SECCTL' for t in out & {'TURNS_ON', 'TURNS_OFF'}}
    if re.search(r'NOPASSWD:\s*ALL\b', joined):
        out.add('GRANT_ALL')
    elif 'NOPASSWD:' in joined:
        out.add('GRANT_SCOPED')
    for k, w in enumerate(rest):
        if w in ('-v', '--volume', '--mount') and k + 1 < len(rest) and re.match(r'^/:/|^/:\w|source=/,', rest[k + 1]):
            out.add('HOST_ROOT_MOUNT')
        if re.match(r'^-v/:/', w) or re.match(r'^--volume=/:/', w):
            out.add('HOST_ROOT_MOUNT')
        if w == '--privileged' or w.lower() in ('--privileged=true', '--privileged=1'):
            out.add('PRIVILEGED')
        if FIXTURE.search(w):
            out.add('TGT=FIXTURE')
    out.discard('')
    return out


def semantic_markers(text):
    return list(_semantic_markers_cached(text))


@functools.lru_cache(maxsize=4096)
def _semantic_markers_cached(text):
    found = set()
    for seg in segments(text):
        head, rest = head_and_rest(seg)
        if head:
            found |= segment_markers(head, rest)
    return sorted(found)


def kv1(text):
    return g_features(text) + semantic_markers(text)


# ---- kv2: flow markers (what is uploaded, what is killed, where decoded data goes, key use) ----
UPLOADERS = {'curl', 'wget', 'nc', 'ncat', 'netcat', 'socat', 'scp', 'rsync', 'invoke-webrequest',
             'invoke-restmethod', 'iwr', 'irm', 'ftp', 'sftp'}
UPLOAD_FLAG = re.compile(r'^(-d|--data(-binary|-raw|-urlencode|-ascii)?|-F|--form|-T|--upload-file|--post-file(=.*)?|'
                         r'--post-data(=.*)?|-InFile|-Body)$', re.I)
SECRET_PATH = re.compile(r'(^|[/\\~])(\.ssh/id_[a-z0-9]+|\.aws/credentials|\.env(\.\w+)?|\.netrc|\.pgpass|'
                         r'\.git-credentials|\.kube/config|\.docker/config\.json|shadow|id_[a-z0-9]+)$', re.I)
ENV_DUMP = {'printenv', 'env', 'set', 'export', 'get-childitem'}
DECODERS = {'base64', 'xxd', 'certutil', 'openssl', 'uudecode', 'base32'}
SHELLS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'python', 'python3', 'perl', 'ruby', 'node', 'iex',
          'invoke-expression', 'powershell', 'pwsh', 'cmd', 'source', '.', 'eval'}
CRED_EXAMPLE = re.compile(r'(AKIA[0-9A-Z]{0,16}EXAMPLE|EXAMPLE[A-Z0-9]*KEY|sk-[a-z-]*example|example[-_]?(key|token|secret))', re.I)


def classify_source(seg):
    head, rest = head_and_rest(seg)
    if head is None:
        return 'OTHER'
    if head in ENV_DUMP and not [w for w in rest if not w.startswith('-')]:
        return 'SECRET'
    args = [w for w in rest if not w.startswith('-')]
    if head in ('echo', 'printf', 'write-output') and args and not any('$' in a or '`' in a for a in args):
        return 'LITERAL'
    for a in args:
        if a.endswith('.pub'):
            return 'PUBLIC_KEY'
        if SECRET_PATH.search(a):
            return 'SECRET'
    if any(re.search(r'(^|/)(README|CHANGELOG|LICENSE)|\.(md|txt|json|ya?ml|csv|log)$', a, re.I) for a in args):
        return 'PROJECT'
    return 'OTHER'


def raw_pipelines(text):
    return list(_raw_pipelines_cached(text))


@functools.lru_cache(maxsize=4096)
def _raw_pipelines_cached(text):
    """Pipelines as lists of segments (word lists); splits on | inside, on ; && || newline between."""
    from .tokens import TOKEN, mask_heredocs
    pipes, pipe, seg = [], [], []
    for t in re.findall(r'\n|' + TOKEN.pattern, mask_heredocs(text)):
        if t == '|':
            pipe.append(seg); seg = []
        elif t in (';', '&&', '||', '&', '\n', '(', ')', '$('):
            pipe.append(seg); pipes.append([s for s in pipe if s]); pipe, seg = [], []
        elif t in ('<', '>', '>>') or re.fullmatch(r'\d*>&\d*', t):
            seg.append(t)
        else:
            seg.append(t[1:-1] if t[:1] in '\'"' and t[-1:] == t[:1] and len(t) > 1 else t)
    pipe.append(seg); pipes.append([s for s in pipe if s])
    return [p for p in pipes if p]


def flow_markers(text):
    return list(_flow_markers_cached(text))


@functools.lru_cache(maxsize=4096)
def _flow_markers_cached(text):
    out = set()
    if CRED_EXAMPLE.search(text):
        out.add('CRED_EXAMPLE')
    for pipe in raw_pipelines(text):
        heads = [head_and_rest([w for w in s if w not in ('<', '>', '>>')])[0] for s in pipe]
        for i, (seg, head) in enumerate(zip(pipe, heads)):
            if head is None:
                continue
            rest = [w for w in head_and_rest([w for w in seg if w not in ('<', '>', '>>')])[1]]
            # uploads: data from stdin (@-) takes the class of the previous segment; @file / -T file their own
            if head in UPLOADERS:
                is_upload = any(UPLOAD_FLAG.match(w) for w in rest) or (head in ('nc', 'ncat', 'netcat', 'socat') and i > 0) \
                    or (head in ('scp', 'rsync') and any(':' in w for w in rest))
                if is_upload:
                    src = None
                    for k, w in enumerate(rest):
                        val = w.split('=', 1)[1] if '=' in w and UPLOAD_FLAG.match(w.split('=')[0]) else (rest[k + 1] if UPLOAD_FLAG.match(w) and k + 1 < len(rest) else None)
                        # multipart form fields: -F name=@file / -F name=<file  ->  @file / <file
                        fm = re.match(r'^[\w.-]+=([@<].+)$', val) if val else None
                        if fm:
                            val = '@' + fm.group(1)[1:]
                        if val and val.startswith('@') and val != '@-':
                            src = classify_source(['cat', val[1:]])
                        elif val and (w in ('-T', '--upload-file') or w.lower() == '-infile'):
                            src = classify_source(['cat', val])
                        elif val and val != '@-' and not val.startswith('@'):
                            src = 'LITERAL' if not CRED_EXAMPLE.search(val) else 'LITERAL'
                    if src is None and i > 0:
                        prev = [w for w in pipe[i - 1] if w not in ('<', '>', '>>')]
                        src = classify_source(prev)
                        if src == 'OTHER' and '<' in pipe[i - 1]:
                            j = pipe[i - 1].index('<')
                            if j + 1 < len(pipe[i - 1]):
                                src = classify_source(['cat', pipe[i - 1][j + 1]])
                    out.add('UPLOAD_OF=' + (src or 'OTHER'))
            if head in ('kill', 'taskkill', 'stop-process', 'pkill', 'killall', 'skill'):
                broad = head in ('killall', 'pkill', 'skill') and any(w in ('-u', '-U') for w in rest) \
                    or any(w in ('-1', '/im', '*') or w.startswith('-1') for w in rest) or head == 'killall5'
                single = all(re.fullmatch(r'[-/]?\w+', w) for w in rest) and any(re.fullmatch(r'\d{2,}', w) for w in rest)
                out.add('KILL_BROAD' if broad else 'KILL_ONE' if single else 'KILL_OTHER')
            if head in DECODERS and any(w in ('-d', '--decode', '-D', '-decode', '-r') or re.fullmatch(r'-[a-z]*d[a-z]*', w) for w in rest):
                later = heads[i + 1:]
                if any(h in SHELLS for h in later if h):
                    out.add('DECODE->INTERP')
                elif '>' in seg or '>>' in seg or any(h in ('tee',) for h in later if h):
                    out.add('DECODE->FILE')
            if head in ('ssh', 'scp', 'sftp') and '-i' in rest:
                out.add('KEY_USE')
    return sorted(out)


def kv2(text):
    return g_features(text) + semantic_markers(text) + flow_markers(text)


# ---- kv3: credential literals, git exec config, persistence targets, wider secret paths ----
CRED_FORMAT = re.compile(r'(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|'
                         r'xox[abposr]-[A-Za-z0-9-]{10,}|sk-(proj-|ant-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,}|'
                         r'-----BEGIN [A-Z ]*PRIVATE KEY-----|glpat-[A-Za-z0-9_-]{20,})')
NET_HEADS = UPLOADERS | {'ssh', 'telnet', 'nslookup', 'dig', 'host', 'ping'}
GIT_EXEC_KEYS = re.compile(r'^(core\.(sshcommand|fsmonitor|hookspath|pager|editor|askpass|gitproxy)|'
                           r'credential\.helper|alias\..+|diff\..+\.(textconv|command)|filter\..+\.(clean|smudge|process)|'
                           r'uploadpack\.packobjectshook|sequence\.editor)$', re.I)
PERSIST_TARGET = re.compile(r'(authorized_keys2?|/\.(bashrc|bash_profile|profile|zshrc|zprofile|zshenv|bash_logout)$|'
                            r'/etc/(crontab|cron\.[a-z]+/|profile(\.d/)?|rc\.local|ld\.so\.preload|systemd/|init\.d/)|'
                            r'/var/spool/cron|/Library/Launch(Agents|Daemons)/|/\.config/autostart/|'
                            r'/lib/systemd/|\.git/hooks/[a-z-]+$)', re.I)
SECRET_EXTRA = re.compile(r'(/proc/(self|\d+)/environ|\.kube/config|\.config/gh/hosts\.yml|\.config/gcloud/|'
                          r'\.azure/|keys\.json$|credentials\.json$|service[-_]account.*\.json$|\.npmrc$|\.pypirc$|'
                          r'\.vault-token|\.terraform\.d/credentials)', re.I)


def risk_markers(text):
    return list(_risk_markers_cached(text))


@functools.lru_cache(maxsize=4096)
def _risk_markers_cached(text):
    out = set()
    lit = CRED_FORMAT.findall(text)
    if lit and not CRED_EXAMPLE.search(text):
        out.add('CRED_LITERAL')
    for pipe in raw_pipelines(text):
        for seg in pipe:
            clean = [w for w in seg if w not in ('<', '>', '>>')]
            head, rest = head_and_rest(clean)
            if head is None:
                continue
            if 'CRED_LITERAL' in out and head in NET_HEADS:
                out.add('CRED_LITERAL@NET')
            for k, w in enumerate(seg):
                target = None
                if w in ('>', '>>') and k + 1 < len(seg):
                    target = seg[k + 1]
                elif w.startswith('--output=') or w.startswith('--output-file='):
                    target = w.split('=', 1)[1]
                if target:
                    if re.search(r'(^|/)\.git[/\\]config$', target) or re.search(r'\.git[/\\]hooks[/\\][a-z-]+$', target):
                        out.add('GIT_EXEC')
                    if PERSIST_TARGET.search(target):
                        out.add('TGT=PERSIST')
            if head == 'git' and 'config' in rest:
                i = rest.index('config')
                keys = [w for w in rest[i + 1:] if not w.startswith('-')]
                if keys and GIT_EXEC_KEYS.match(keys[0]) and len(keys) > 1:
                    out.add('GIT_EXEC')
            if head in ('tee', 'cp', 'mv', 'install', 'ln', 'dd', 'sed') and any(PERSIST_TARGET.search(w) for w in rest):
                out.add('TGT=PERSIST')
            if any(SECRET_EXTRA.search(w) for w in rest):
                out.add('TGT=SECRET')
    return sorted(out)


def kv3(text):
    return g_features(text) + semantic_markers(text) + flow_markers(text) + risk_markers(text)


# ---- kf: patronus.facts/1 (fixed mode) flattened into tokens, PLAN_FACTS step 6 ----
def fact_tokens(text):
    """Deterministic flattening of the facts of one command into model tokens (set, sorted)."""
    from .facts.extract import extract
    f = extract(text, mode='fixed')
    out = {'F:DIA=' + f['dialect']}
    for s in f['segments']:
        v, r = s['verb'] or 'NONE', s.get('role') or 'UNK'
        out |= {'F:V=' + v, 'F:R=' + r, 'F:VR=' + v + ':' + r}
        out |= {'F:OP=' + o for o in s['ops']}
        out |= {f"F:O={o['access']}@{o['class']}" for o in s['objects'] if o['access']}
        out |= {'F:C=' + o['class'] for o in s['objects']}
        out |= {f"F:S={x['domain']}:{x['polarity']}" for x in s['settings']}
        out |= {'F:SQL=' + k for k in s.get('sql', [])}
        out |= {'F:NET=' + n['scope'] for n in s['network']}
        out |= {'F:G=' + g for g in s['grants']}
        if s.get('sensitive'):
            out.add('F:SENS')
        if s.get('nested'):
            out |= {'F:NEST=' + s['nested'], 'F:NEST_V=' + v}
        if s['container']['host_root_mount']:
            out.add('F:HRM')
        if s['container']['privileged']:
            out.add('F:PRIV')
    for x in f['flows']:
        out |= {f"F:FLOW={x['data']}>{x['sink']}", f"F:FLOWV={x['data']}>{x['sink']}>{x['via']}"}
    out |= {'F:OBJ=' + o['class'] for o in f['objects']}
    out |= {'F:A=' + a for a in f['atoms']}
    return sorted(out)


def kf1(text):
    """kv3 (live tokens + legacy markers) + fact tokens."""
    return kv3(text) + fact_tokens(text)
