"""patronus.facts/1 extractor. Deterministic, no I/O, never executes text.

extract(command, context=None, prior_facts=None) -> facts dict (see schema.py)

Segmentation fixes over the plain tokenizer: PowerShell `$x=` assignment prefixes, cmd `rem`/`::` comments,
shell keywords (if/then/do/..., POSIX only), Python code lines and heredoc bodies that are data (code for an
interpreter, or cat/tee into a data file) are not command heads. Verbs come from the shell vocabulary
(shell_vocab_v1.csv) at the subcommand position, falling back to the marker verb classes.

context      {cwd, home, repo_root, dialect}, supplied by the security harness (trusted). Relative paths are
             resolved lexically; paths under repo_root in fixture dirs become FIXTURE, other repo files PROJECT.
             Context may lower risk as well as raise it.
prior_facts  facts of earlier commands, passed by the harness (Patronus stores nothing). Links the current
             command to them: upload of a path that earlier received secret material -> flow SECRET->NET via
             PRIOR_PATH; execution of a path that was downloaded earlier -> flow REMOTE->EXEC via PRIOR_PATH.
"""
import ipaddress
import posixpath
import re

from .. import features as feats
from .. import markers as am
from .. import segments as hfacts
from .. import tokens as shell_tokens
from ..tokens import HEREDOC_MASK, TOKEN, heredoc_delimiter, relations
from . import vocab
from .schema import VERSION

ACCESS_OF_VERB = {'READ': 'READ', 'MUTATE': 'WRITE', 'DELETE': 'DELETE', 'EXEC': 'EXECUTE', None: None}

# Legacy marker <-> structured fact tables, used in both directions (extract here, legacy.py back).
RELATION_FLOWS = {
    'DL->PIPE->INTERP': ('REMOTE', 'INTERP', 'PIPE'),
    'DL->SUBST->INTERP': ('REMOTE', 'INTERP', 'SUBST'),
    'DL->FILE->EXEC': ('REMOTE', 'EXEC', 'SAME_PATH'),
    'DL->PIPE->FILTER': ('REMOTE', 'FILTER', 'PIPE'),
    'DL->FILE': ('REMOTE', 'FILE', 'ARG'),
}
MARKER_FLOWS = {
    'UPLOAD_OF=SECRET': ('SECRET', 'NET', 'UPLOAD'),
    'UPLOAD_OF=PUBLIC_KEY': ('PUBLIC_KEY', 'NET', 'UPLOAD'),
    'UPLOAD_OF=LITERAL': ('LITERAL', 'NET', 'UPLOAD'),
    'UPLOAD_OF=PROJECT': ('PROJECT', 'NET', 'UPLOAD'),
    'UPLOAD_OF=OTHER': ('OTHER', 'NET', 'UPLOAD'),
    'DECODE->INTERP': ('DECODED', 'INTERP', 'PIPE'),
    'DECODE->FILE': ('DECODED', 'FILE', 'REDIRECT'),
    'CRED_LITERAL@NET': ('CRED_LITERAL', 'NET', 'ARG'),
}
MARKER_OBJECTS = {'GIT_EXEC': 'GIT_EXEC_CONFIG', 'TGT=PERSIST': 'PERSIST', 'TGT=SECRET': 'SECRET'}
MARKER_ATOMS = {'KILL_ONE', 'KILL_BROAD', 'KILL_OTHER', 'KEY_USE', 'CRED_EXAMPLE', 'CRED_LITERAL'}

SHELL_KEYWORDS = {'if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac',
                  'function', '{', '}', '[[', ']]', '!', 'select'}
CODE_HEADS = {'def', 'return', 'import', 'from', 'class', 'raise', 'pass', 'try', 'except', 'finally', 'yield',
              'lambda', 'with', 'assert', 'elif', 'else', 'self'}
INTERPRETERS = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'python', 'python3', 'perl', 'ruby', 'node', 'pwsh',
                'powershell', 'source', '.'}
OUTPUT_FLAGS = {'-o', '--output', '-O', '--output-document', '-outfile'}
PWSH_HINT = re.compile(r'\b(Get|Set|New|Remove|Add|Invoke|Start|Stop|Write|Out|Select|Where|ForEach|Test|Import|'
                       r'Export|ConvertTo|ConvertFrom|Enable|Disable|Clear)-[A-Z]\w+|\$env:|\[[A-Za-z.]+\]::', re.I)
CMD_HINT = re.compile(r'(?im)^\s*(rem\s|::|@echo\s|set\s+/[ap]\b|if\s+exist\b)|%[A-Za-z_]+%')


def detect_dialect(text):
    p, c = bool(PWSH_HINT.search(text)), bool(CMD_HINT.search(text))
    return 'MIXED' if p and c else 'POWERSHELL' if p else 'CMD' if c else 'POSIX'


# ---------------------------------------------------------------- segmentation (fixed mode)
# Fixed mode only (the live tokenizer keeps its own list): a cat/tee heredoc into a plain data file is data too,
# so test inputs like `cat > cases.txt <<EOF / DELETE 5 / EOF` do not become DELETE segments. Shell scripts stay shell.
DATA_HEREDOC_FILE = re.compile(
    r'(?:>>?|\btee(?:\s+-a)?)\s*[\'"]?[^\s;&|()<>\'"]+\.(?:txt|csv|tsv|log|md|rst|xml|html?|conf|in|out|dat|ndjson|jsonl)'
    r'[\'"]?(?=[\s;&|()<>]|$)', re.I)


def _data_heredoc_delimiter(line):
    d = heredoc_delimiter(line)
    if d is not None:
        return d
    for s, e in shell_tokens.heredoc_segments(line):
        seg = line[s:e]
        op = shell_tokens.HEREDOC_OP.search(seg)
        if op and seg[op.start() - 1:op.start()] != '<' and shell_tokens._segment_head(seg) in shell_tokens.HEREDOC_WRITERS \
                and DATA_HEREDOC_FILE.search(seg):
            return op.group(2)
    return None


def mask_heredocs_fixed(text):
    out, delimiter = [], None
    for line in text.split('\n'):
        if delimiter is not None:
            if line.strip(' \t\r') == delimiter:
                out.append(line); delimiter = None
            continue
        out.append(line)
        delimiter = _data_heredoc_delimiter(line)
        if delimiter is not None:
            out.append(HEREDOC_MASK)
    return '\n'.join(out)


def _segments_fixed(text, dialect):
    """Command segments with the parser fixes. Yields (words, redirected).
    A `#` comment runs to the end of the line; heredoc terminator lines and the body mask are not commands."""
    # parens stay separators in every dialect: PowerShell (...) / $(...) are subexpressions with their own command
    seps = am.SEPARATORS
    lines = []
    delim = None
    for line in mask_heredocs_fixed(text).split('\n'):
        if delim is not None and line.strip(' \t\r') == delim:
            delim = None
            continue  # terminator line
        if line == HEREDOC_MASK:
            continue
        lines.append(line)
        delim = _data_heredoc_delimiter(line)
    seg, redirect, comment = [], False, False
    for t in re.findall(r'\n|' + TOKEN.pattern, '\n'.join(lines)):
        if comment and t != '\n':
            continue
        comment = False
        if t in seps or t.startswith('#'):
            if seg:
                yield seg, redirect
            seg, redirect, comment = [], False, t.startswith('#')
            continue
        if t in ('>', '>>') or re.fullmatch(r'\d*>&\d*', t):
            redirect = redirect or t in ('>', '>>')
            continue
        if t == '<':
            continue
        seg.append(t[1:-1] if t[:1] in '\'"' and t[-1:] == t[:1] and len(t) > 1 else t)
    if seg:
        yield seg, redirect


def _strip_fixed(seg, dialect):
    """Words of a segment after dropping shell keywords and `$x=` / `$x =` assignments; [] for code lines
    and cmd comments, which have no command head."""
    words = list(seg)
    while words:
        w = words[0]
        if w.lower() in SHELL_KEYWORDS and dialect not in ('POWERSHELL', 'CMD'):
            words = words[1:]
            continue
        m = re.fullmatch(r'\$[\w:.]+=(.*)', w)
        if m:
            words = ([m.group(1)] if m.group(1) else []) + words[1:]
            continue
        if re.fullmatch(r'\$[\w:.]+', w) and len(words) > 1 and words[1] == '=':
            words = words[2:]
            continue
        break
    if not words or not re.search(r'\w', words[0]):
        return []
    first = words[0].lower().rstrip(':')
    if first == 'rem' or words[0].startswith('::') or first in CODE_HEADS:
        return []
    return words


# ---------------------------------------------------------------- objects and context
def _resolve(path, ctx):
    """Absolute path for a path-like argument, lexically against the harness context; None if unknown."""
    if not path or path.startswith('-') or '://' in path:
        return None
    home, p = ctx.get('home'), path
    if home and (p == '~' or p.startswith('~/')):
        p = home + p[1:]
    elif home and re.match(r'^\$(HOME|\{HOME\})(/|$)', p):
        p = home + re.sub(r'^\$(HOME|\{HOME\})', '', p)
    if not p.startswith('/') and ctx.get('cwd') and not re.match(r'^[A-Za-z]:\\', p) and '$' not in p:
        p = posixpath.join(ctx['cwd'], p)
    return posixpath.normpath(p) if p.startswith('/') else None


def _context_class(abs_path, cls, ctx):
    """Trusted repo context refines the class: repo fixtures are FIXTURE, other repo files PROJECT
    (secret, persistence and git exec paths keep their class)."""
    repo = (ctx.get('repo_root') or '').rstrip('/')
    if not abs_path or not repo or not (abs_path == repo or abs_path.startswith(repo + '/')):
        return cls
    if feats.FIXTURE.search(abs_path[len(repo):]):
        return 'FIXTURE'
    return cls if cls in ('SECRET', 'PERSIST', 'GIT_EXEC_CONFIG') else 'PROJECT'


WRITE_LAST = {'cp', 'mv', 'install', 'ln', 'rsync', 'scp', 'copy', 'xcopy', 'robocopy', 'copy-item', 'move-item'}
WRITERS = {'tee', 'touch', 'truncate', 'set-content', 'add-content', 'out-file', 'mkdir', 'dd'}
HOST_ARG = re.compile(r'^(?:[\w.+-]+@)?(\[[0-9a-fA-F:]+\]|[A-Za-z0-9][A-Za-z0-9.-]*)(?::|$)')
URL = re.compile(r'^[a-z][a-z0-9+.-]*://(?:[^/@\s]*@)?(\[[0-9a-fA-F:]+\]|[^/:?#\s]+)', re.I)
NET_PROGRAMS = hfacts.DOWNLOADERS | hfacts.CONNECTORS | {'ping', 'dig', 'nslookup', 'host', 'nmap', 'masscan', 'autossh',
                                                      'mosh', 'git', 'docker', 'kubectl', 'psql', 'mysql', 'redis-cli'}


def redirect_targets(text):
    """Words after > / >> (WRITE / APPEND), from the raw pipeline tokens."""
    out = {}
    for pipe in feats.raw_pipelines(text):
        for seg in pipe:
            for j, w in enumerate(seg):
                if w in ('>', '>>') and j + 1 < len(seg):
                    out[seg[j + 1]] = 'APPEND' if w == '>>' else 'WRITE'
    return out


def _access(w, k, head, rest, verb, redirects):
    """Access of one argument: redirect target, copy/move destination, writer argument, else from the verb."""
    if w in redirects:
        return redirects[w]
    args = [i for i, x in enumerate(rest) if not x.startswith('-')]
    if head in WRITE_LAST and len(args) >= 2:
        return 'WRITE' if k == args[-1] else 'READ'
    if head == 'tee':
        return 'APPEND' if '-a' in rest or '--append' in rest else 'WRITE'
    if head in WRITERS or (head == 'sed' and any(x == '-i' or x.startswith(('-i', '--in-place')) for x in rest)):
        return 'WRITE'
    return ACCESS_OF_VERB[verb]


def scope_of(host):
    h = host.strip('[]').lower().rstrip('.')
    if h in ('localhost', 'localhost.localdomain') or h.endswith('.localhost'):
        return 'LOOPBACK'
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        if '$' in h or '%' in h or '{' in h:
            return 'UNKNOWN'
        if h.endswith(('.local', '.internal', '.lan', '.svc', '.cluster.local', '.corp', '.home.arpa')) or '.' not in h:
            return 'PRIVATE'
        return 'PUBLIC'
    if ip.is_loopback:
        return 'LOOPBACK'
    if ip.is_link_local:
        return 'LINK_LOCAL'
    if ip.is_private or ip.is_reserved or ip.is_unspecified:
        return 'PRIVATE'
    return 'PUBLIC'


def network_of(head, rest):
    """Remote endpoints named by a segment: URLs anywhere, [user@]host: for ssh/scp/rsync style tools,
    and the first host-like argument of connectors (nc host port, ssh host, ping host)."""
    prog = hfacts.program(head)
    out = []
    for w in rest:
        m = URL.match(w)
        if m:
            out.append(m.group(1))
    if prog in NET_PROGRAMS and not out:
        for w in rest:
            if w.startswith('-') or '/' in w.split(':', 1)[0]:
                continue
            m = HOST_ARG.match(w)
            bare_ok = prog in (hfacts.CONNECTORS - {'scp', 'rsync', 'sftp'}) | {'ping', 'dig', 'nslookup', 'host', 'mosh',
                                                                                'autossh'}
            if m and ('@' in w or ':' in w or bare_ok):
                host = m.group(1)
                if re.fullmatch(r'\d+', host) or (':' not in w and '@' not in w and '.' not in host
                                                   and host not in ('localhost',)):
                    continue  # bare port numbers and words without a dot are not hosts here
                out.append(host)
                if prog not in ('scp', 'rsync'):
                    break
    return [{'host': h, 'scope': scope_of(h)} for h in dict.fromkeys(out)]


def stdin_is_code(head, rest):
    """Does an interpreter at this pipeline position run its stdin as code? False when it gets a script file,
    -c/-m/-e code or a command string; `-`, `-s` and no arguments mean stdin. Unknown forms count as code."""
    if head in ('iex', 'invoke-expression'):
        return True
    flags = [w.lower() for w in rest if w.startswith('-')]
    pos = [w for w in rest if not w.startswith('-')]
    if head in ('sh', 'bash', 'zsh', 'dash', 'ksh'):
        if '-s' in flags or (rest and rest[0] == '-'):
            return True
        return not ('-c' in flags or any(re.fullmatch(r'-[a-z]*c[a-z]*', f) for f in flags) or pos)
    if head in ('pwsh', 'powershell'):
        return any(f in ('-command', '-c') for f in flags) and '-' in rest or not (pos or flags)
    if '-' in rest:
        return True
    if any(f in ('-c', '-m', '-e', '-E', '-p', '-n', '--eval', '--print', '-r') for f in flags) or pos:
        return False
    return True


def _remote_interp_is_filter(text):
    """True if every downloader -> interpreter pipeline hands the data to a script or -c code, not to stdin
    as code (e.g. `curl ... | python3 -m json.tool`)."""
    seen = False
    for pipe in feats.raw_pipelines(text):
        heads = [am.head_and_rest(_clean(sg)) for sg in pipe]
        dl = [k for k, (h, _) in enumerate(heads) if h and hfacts.program(h) in hfacts.DOWNLOADERS]
        for k, (h, rest) in enumerate(heads):
            if h in feats.SHELLS and dl and dl[0] < k:
                seen = True
                if stdin_is_code(h, rest):
                    return False
    return seen


def _with_flag_verbs(prog, rest, verb):
    """Verb flags (--delete, --remove, -D on branch, find -exec) still count next to the vocabulary verb;
    the strongest verb wins."""
    cands = [verb or 'NONE']
    for w in rest:
        m = am.FLAG_VERB.match(w)
        if m:
            cands += [name for name, words in am.CLASS_OF if m.group(1).lower() in words]
    if prog == 'find' and any(w in ('-exec', '-execdir', '-ok', '-okdir') for w in rest):
        cands.append('EXEC')
    best = max(cands, key=lambda v: vocab.SEVERITY[v])
    return None if best == 'NONE' else best


def _segment(i, seg, head, rest, redirected, rel, ctx, redirects):
    prog = hfacts.program(head)
    hit = vocab.lookup(prog, rest)
    if hit:
        # vocabulary verb at the subcommand position; arguments elsewhere (file names like `clean`) do not count
        verb, role, sensitive, key = hit
        verb = None if verb == 'NONE' else verb
        if prog == 'sed' and any(x == '-i' or x.startswith(('-i', '--in-place')) for x in rest):
            verb = 'MUTATE'
        verb = _with_flag_verbs(prog, rest, verb)
    else:
        verb, role, sensitive, key = am.verb_class(head, rest), None, False, None
    objects = []
    for k, w in enumerate(rest):
        tc = am.target_class(w, head in am.FILE_HEADS)
        if tc:
            ab = _resolve(w, ctx)
            o = {'value': w, 'class': _context_class(ab, tc, ctx), 'access': _access(w, k, head, rest, verb, redirects),
                 'abs': ab}
            if o['class'] != tc:
                o['legacy_class'] = tc
            objects.append(o)
        if feats.PERSIST_TARGET.search(w):
            # persistence location with its access (legacy TGT=PERSIST is a whole-command marker without access)
            objects.append({'value': w, 'class': 'PERSIST', 'access': _access(w, k, head, rest, verb, redirects),
                            'abs': _resolve(w, ctx), 'legacy_class': None})
    marks = feats.segment_markers(head, rest)
    return {'id': i, 'head': head, 'program': prog, 'verb': verb, 'role': role, 'sensitive': sensitive, 'vocab': key,
            'ops': hfacts.segment_ops(seg, head, rest, redirected, rel, verb), 'objects': objects, 'kv': am.values(rest),
            'settings': [{'domain': 'SECCTL' if 'SECCTL' in marks else 'OTHER', 'polarity': t[len('TURNS_'):]}
                         for t in ('TURNS_ON', 'TURNS_OFF') if t in marks],
            'secctl': 'SECCTL' in marks, 'grants': sorted(m[len('GRANT_'):] for m in marks if m.startswith('GRANT_')),
            'container': {'host_root_mount': 'HOST_ROOT_MOUNT' in marks, 'privileged': 'PRIVILEGED' in marks},
            'fixture': 'TGT=FIXTURE' in marks, 'redirected': redirected, 'network': network_of(head, rest),
            'argv': [w.lower() for w in rest], 'rest_raw': rest}


# ---------------------------------------------------------------- cross-command facts
def _clean(seg):
    return [w for w in seg if w not in ('<', '>', '>>')]


def _writes_and_downloads(text):
    """Files that receive secret material, and files produced by downloads (for prior_facts linking)."""
    writes, downloads = [], []
    for pipe in feats.raw_pipelines(text):
        for k, seg in enumerate(pipe):
            head, rest = am.head_and_rest(_clean(seg))
            if head is None:
                continue
            piped_secret = k > 0 and feats.classify_source(_clean(pipe[k - 1])) == 'SECRET'
            for j, w in enumerate(seg):
                if w in ('>', '>>') and j + 1 < len(seg):
                    if piped_secret or feats.classify_source(_clean(seg[:j])) == 'SECRET':
                        writes.append({'path': seg[j + 1], 'data': 'SECRET'})
            args = [a for a in rest if not a.startswith('-')]
            if head == 'tee' and piped_secret:
                writes += [{'path': a, 'data': 'SECRET'} for a in args]
            elif head in ('cp', 'install') and len(args) >= 2 and feats.classify_source(['cat', args[0]]) == 'SECRET':
                writes.append({'path': args[-1], 'data': 'SECRET'})
            if hfacts.program(head) in hfacts.DOWNLOADERS:
                for j, w in enumerate(rest):
                    # -o / -O, also bundled short flags that end in it (curl -sSLo FILE, wget -qO FILE)
                    short = w.lower() in OUTPUT_FLAGS or re.match(r'^-[A-Za-z]+[oO]$', w)
                    if short and j + 1 < len(rest) and rest[j + 1] != '-':
                        downloads.append(rest[j + 1])
                    elif re.match(r'^--output(-document)?=', w) and not w.endswith('=-'):
                        downloads.append(w.split('=', 1)[1])
    return writes, downloads


def _upload_sources(text):
    """Local paths sent by an uploader (@file, -T file, -InFile file, scp/rsync local args)."""
    out = []
    for pipe in feats.raw_pipelines(text):
        for seg in pipe:
            head, rest = am.head_and_rest(_clean(seg))
            if head not in feats.UPLOADERS:
                continue
            for k, w in enumerate(rest):
                key = w.split('=', 1)[0]
                if not (feats.UPLOAD_FLAG.match(w) or ('=' in w and feats.UPLOAD_FLAG.match(key))):
                    continue
                val = w.split('=', 1)[1] if '=' in w and feats.UPLOAD_FLAG.match(key) else (
                    rest[k + 1] if k + 1 < len(rest) else '')
                fm = re.match(r'^[\w.-]+=([@<].+)$', val)
                val = '@' + fm.group(1)[1:] if fm else val
                if val.startswith('@') and val != '@-':
                    out.append(val[1:])
                elif w in ('-T', '--upload-file') or w.lower() == '-infile':
                    out.append(val)
            if head in ('scp', 'rsync'):
                out += [w for w in rest if not w.startswith('-') and ':' not in w]
    return out


def _executed_paths(segments_raw):
    """Paths run as programs (./x.sh, /tmp/x) or handed to an interpreter (bash x.sh)."""
    out = []
    for seg in segments_raw:
        words = [w for w in seg if not re.fullmatch(r'[A-Za-z_]\w*=.*', w) and am.base(w) not in am.PREFIXES]
        if not words:
            continue
        if '/' in words[0] or words[0].startswith('.'):
            out.append(words[0])
        if am.base(words[0]) in INTERPRETERS:
            out += [w for w in words[1:] if not w.startswith('-')][:1]
    return out


def _link_prior(command, segments_raw, prior_facts, ctx):
    norm = lambda p: _resolve(p, ctx) or posixpath.normpath(p)  # noqa: E731
    secret = {norm(w['path']) for pf in prior_facts for w in pf.get('writes', []) if w['data'] == 'SECRET'}
    downloaded = {norm(p) for pf in prior_facts for p in pf.get('downloads', [])}
    flows = []
    if secret and any(norm(p) in secret for p in _upload_sources(command)):
        flows.append({'data': 'SECRET', 'sink': 'NET', 'via': 'PRIOR_PATH'})
    if downloaded and any(norm(p) in downloaded for p in _executed_paths(segments_raw)):
        flows.append({'data': 'REMOTE', 'sink': 'EXEC', 'via': 'PRIOR_PATH'})
    return flows


# ---------------------------------------------------------------- fixed-mode facts: nested commands, SQL, dumps
NESTED_C = {'sh', 'bash', 'zsh', 'dash', 'ksh', 'su'}
SSH_VALUE_FLAGS = {'-i', '-p', '-o', '-l', '-F', '-J', '-L', '-R', '-D', '-b', '-c', '-E', '-e', '-m', '-O', '-Q', '-S', '-W', '-w'}
DB_CLIENTS = {'mysql', 'mariadb', 'psql', 'sqlite3', 'sqlcmd', 'clickhouse-client', 'mongo', 'mongosh', 'duckdb'}
SQL_FLAGS = {'-e', '--execute', '-c', '--command', '-q', '-Q', '--query', '--eval'}
DUMPERS = {'pg_dump', 'pg_dumpall', 'mysqldump', 'mariadb-dump', 'mongodump', 'mongoexport', 'redis-cli'}
SQL_KINDS = [('SQL_EXEC', re.compile(r'\b(create\s+function\b.*\bsoname\b|load_file\s*\(|into\s+(out|dump)file\b|'
                                    r'copy\b.*\bprogram\b|xp_cmdshell|sys_exec|sys_eval)', re.I | re.S)),
             ('DELETE_ALL', re.compile(r'\bdelete\s+from\s+[\w."`\[\]]+\s*(;|$)|\btruncate\b', re.I)),
             ('DROP', re.compile(r'\bdrop\s+(table|database|schema|user|role|index|view)\b', re.I)),
             ('DELETE', re.compile(r'\bdelete\s+from\b', re.I)),
             ('WRITE', re.compile(r'\b(insert\s+into|update\s+[\w."`]+\s+set|alter\s+(table|user|role)|create\s+(table|user|role)|'
                                  r'grant\b|revoke\b)', re.I)),
             ('READ', re.compile(r'\b(select|show|describe|explain)\b', re.I))]
SQL_OPS = {'SQL_EXEC': 'EXECUTE', 'DELETE_ALL': 'DELETE', 'DROP': 'DELETE', 'DELETE': 'DELETE', 'WRITE': 'CONFIG_CHANGE',
           'READ': 'READ'}


def nested_command(prog, rest):
    """(inner command string, 'local'|'remote') for sh -c STR, pwsh -Command STR, cmd /c STR, su -c STR,
    ssh [opts] host STR; else None."""
    low = [w.lower() for w in rest]
    if prog in NESTED_C | {'sudo'} and '-c' in low:
        k = low.index('-c')
        return (rest[k + 1], 'local') if k + 1 < len(rest) else None
    if prog in ('pwsh', 'powershell'):
        for flag in ('-command', '-c'):
            if flag in low:
                k = low.index(flag)
                return (' '.join(rest[k + 1:]), 'local') if k + 1 < len(rest) else None
    if prog == 'cmd' and ('/c' in low or '/k' in low):
        k = low.index('/c') if '/c' in low else low.index('/k')
        return (' '.join(rest[k + 1:]), 'local') if k + 1 < len(rest) else None
    if prog in ('ssh', 'autossh'):
        k = 0
        while k < len(rest) and rest[k].startswith('-'):
            k += 2 if rest[k] in SSH_VALUE_FLAGS else 1
        if k + 1 < len(rest):
            return ' '.join(rest[k + 1:]), 'remote'
    return None


def sql_kinds(prog, rest):
    """Statement kinds of SQL given to a database client via -e/-c/--query (or sqlite3 db "SQL")."""
    if prog not in DB_CLIENTS:
        return []
    texts = []
    for k, w in enumerate(rest):
        lw = w.lower()
        if lw in SQL_FLAGS and k + 1 < len(rest):
            texts.append(rest[k + 1])
        elif '=' in lw and lw.split('=', 1)[0] in SQL_FLAGS:
            texts.append(w.split('=', 1)[1])
    if prog in ('sqlite3', 'duckdb'):
        texts += [w for w in rest[1:] if not w.startswith('-')]
    kinds = []
    for t in texts:
        kinds += [name for name, rx in SQL_KINDS if rx.search(t)]
    return sorted(set(kinds))


def sed_settings(prog, rest):
    """Settings changed by sed -i 's/OLD/NEW/' (e.g. SELINUX=disabled in /etc/selinux/config)."""
    if prog != 'sed' or not any(x == '-i' or x.startswith(('-i', '--in-place')) for x in rest):
        return []
    files = ' '.join(w for w in rest if not w.startswith('-') and not re.match(r'^s(.).*\1', w))
    out = []
    for w in rest:
        m = re.match(r'^s(.)(.*?)\1(.*?)\1[gimx]*$', w)
        if not m:
            continue
        for key, val in re.findall(r'([A-Za-z_][\w.-]{1,60})\s*[=: ]\s*([^\s,;]+)', m.group(3)):
            t = feats.turns(key, val)
            if t:
                dom = 'SECCTL' if feats.SECCTL.search(key + ' ' + files) else 'OTHER'
                out.append({'domain': dom, 'polarity': t[len('TURNS_'):]})
    return out


def db_dump_flows(text, writes):
    """Database dumps piped into a network uploader, or written to a file (recorded in writes)."""
    flows = []
    for pipe in feats.raw_pipelines(text):
        heads = [am.head_and_rest(_clean(sg)) for sg in pipe]
        for k, (h, rest) in enumerate(heads):
            if h not in DUMPERS or (h == 'redis-cli' and '--rdb' not in rest):
                continue
            if any(h2 in feats.UPLOADERS for h2, _ in heads[k + 1:] if h2):
                flows.append({'data': 'DB_DUMP', 'sink': 'NET', 'via': 'PIPE'})
            seg = pipe[k]
            for j, w in enumerate(seg):
                if w in ('>', '>>') and j + 1 < len(seg):
                    writes.append({'path': seg[j + 1], 'data': 'DB_DUMP'})
            for j, w in enumerate(rest):
                if w in ('-f', '--file', '-o', '--out', '--result-file') and j + 1 < len(rest):
                    writes.append({'path': rest[j + 1], 'data': 'DB_DUMP'})
    return flows


def same_command_links(text, writes, ctx):
    """Upload of a path that this same command earlier filled with secret or dump data."""
    norm = lambda p: _resolve(p, ctx) or posixpath.normpath(p)  # noqa: E731
    by_path = {norm(w['path']): w['data'] for w in writes}
    out = []
    for p in _upload_sources(text):
        d = by_path.get(norm(p))
        if d:
            out.append({'data': d, 'sink': 'NET', 'via': 'SAME_PATH'})
    return out




# ---------------------------------------------------------------- entry point
QUOTE_RUN = re.compile(r"(?<![^\s;|&(])((?:[A-Za-z0-9_./-]*(?:'[A-Za-z0-9_./-]*'|\"[A-Za-z0-9_./-]*\"))+[A-Za-z0-9_./-]*)(?=[\s;|&)]|$)")
CARET_RUN = re.compile(r'(?<![^\s;|&(])([A-Za-z0-9_.-](?:\^[A-Za-z0-9_.-])+)(?=[\s;|&)]|$)')
BACKSLASH_RUN = re.compile(r'(?<![^\s;|&(])((?:\\?[A-Za-z0-9_.-])*\\[A-Za-z][A-Za-z0-9_.\\-]*)(?=[\s;|&)]|$)')


def deobfuscate(text, dialect):
    """Shell quote removal inside single words ('r''m', \"r\"m, r\\m) and cmd caret escapes (r^m^d^i^r).
    Only words made of plain characters are rewritten, so quoted arguments with spaces stay as they are.
    Returns (text, atoms)."""
    atoms = set()

    def unquote(m):
        w = m.group(1)
        if "'" in w or '"' in w:
            atoms.add('OBF_QUOTE')
            return w.replace("'", '').replace('"', '')
        return w
    out = QUOTE_RUN.sub(unquote, text)
    if dialect in ('CMD', 'MIXED') or '^' in text:
        def uncaret(m):
            atoms.add('OBF_CARET')
            return m.group(1).replace('^', '')
        out = CARET_RUN.sub(uncaret, out)

    def unslash(m):
        atoms.add('OBF_BACKSLASH')
        return m.group(1).replace('\\', '')
    if dialect not in ('CMD', 'POWERSHELL', 'MIXED'):
        out = BACKSLASH_RUN.sub(unslash, out)
    return out, atoms


def extract(command, context=None, prior_facts=None, mode='fixed', _depth=0):
    if mode != 'fixed':
        raise ValueError(f'unknown mode {mode!r}: only "fixed" exists')
    ctx = {k: v for k, v in (context or {}).items() if v}
    dialect = ctx.get('dialect') or detect_dialect(command)
    command, obf = deobfuscate(command, dialect)
    rel = relations(command)
    # a bare `:` without redirect is a no-op (often the tail of a code line like `def f():`)
    cands = [([] if seg == [':'] and not red else _strip_fixed(seg, dialect), red)
             for seg, red in _segments_fixed(command, dialect)]
    segments, redirects = [], redirect_targets(command)
    for seg, red in cands:
        head, rest = am.head_and_rest(seg) if seg else (None, [])
        if head is not None:  # NOISE heads stay as segments (role NOISE, no verb): dropping them could hide fragments
            segments.append(_segment(len(segments), seg, head, rest, red, rel, ctx, redirects))
    flows = [dict(zip(('data', 'sink', 'via'), RELATION_FLOWS[r])) for r in rel]
    if 'DL->PIPE->INTERP' in rel and _remote_interp_is_filter(command):
        flows = [dict(f, sink='FILTER') if (f['data'], f['sink'], f['via']) == ('REMOTE', 'INTERP', 'PIPE') else f
                 for f in flows]
    objects, atoms = [], sorted(obf)
    for m in feats.flow_markers(command) + feats.risk_markers(command):
        if m in MARKER_FLOWS:
            flows.append(dict(zip(('data', 'sink', 'via'), MARKER_FLOWS[m])))
        elif m in MARKER_OBJECTS:
            objects.append({'value': None, 'class': MARKER_OBJECTS[m], 'access': None, 'abs': None})
        elif m in MARKER_ATOMS:
            atoms.append(m)
        else:
            raise KeyError(f'unmapped marker {m}')
    if prior_facts:
        flows += _link_prior(command, [s for s, _ in cands], prior_facts, ctx)
    writes, downloads = _writes_and_downloads(command)
    for s in segments:
        s['sql'] = sql_kinds(s['program'], s['rest_raw'])
        s['ops'] = sorted(set(s['ops']) | {SQL_OPS[k] for k in s['sql']})
        s['settings'] += [x for x in sed_settings(s['program'], s['rest_raw']) if x not in s['settings']]
    flows += db_dump_flows(command, writes)
    flows += same_command_links(command, writes, ctx)
    # commands inside strings (sh -c, pwsh -Command, cmd /c, ssh host CMD): their facts join this command
    for s in list(segments):
        nc = nested_command(s['program'], s['rest_raw']) if _depth < 2 else None
        if not nc:
            continue
        inner = extract(nc[0], context=ctx, _depth=_depth + 1)
        for t in inner['segments']:
            segments.append(dict(t, id=len(segments), nested=nc[1], parent=s['id']))
        flows += [f for f in inner['flows'] if f not in flows]
        objects += inner['objects']; atoms += inner['atoms']
        writes += inner['writes']; downloads += inner['downloads']
    for s in segments:
        s.pop('rest_raw', None)
    status = 'NOT_APPLICABLE' if not command.strip() else 'COMPLETE' if segments else 'PARTIAL'
    return {'v': VERSION, 'mode': mode, 'dialect': dialect, 'parse_status': status, 'context': ctx or None,
            'segments': segments, 'flows': flows, 'objects': objects, 'atoms': sorted(set(atoms)),
            'writes': writes, 'downloads': downloads}
