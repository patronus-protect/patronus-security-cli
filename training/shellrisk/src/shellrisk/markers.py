"""Action markers (legacy marker tokens of the kf1 feature block): what a command does, to what, with which value. Text is never executed.

Three marker families, appended to the shell-token block. Each is deterministic and small
enough to port to Rust 1:1:
  VERB=<CLASS> and <head>:<CLASS>      READ / MUTATE / DELETE / EXEC per command segment
  TGT=<CLASS> and <VERB>@<TGT>          target class of path / registry arguments
  VAL=<v>, <key>=<v>                    small integers and boolean-ish literals after a value
                                        flag or in key=value form, which <NUM> otherwise erases
Markers are de-duplicated per text and emitted in sorted order.
"""
import re

from .tokens import mask_heredocs, tokens

SEPARATORS = {'|', '||', '&&', ';', '&', '(', ')', '$(', '\n'}
PREFIXES = {'sudo', 'doas', 'env', 'exec', 'command', 'nohup', 'time', 'timeout', 'nice', 'xargs'}

READ = {'get', 'list', 'ls', 'show', 'describe', 'status', 'query', 'export', 'cat', 'view', 'print',
        'info', 'inspect', 'check', 'logs', 'log', 'top', 'version', 'help', 'diff', 'search', 'find',
        'test', 'verify', 'read', 'dump', 'head', 'tail', 'grep', 'stat', 'which', 'whoami', 'ping',
        'lookup', 'resolve', 'measure', 'select', 'where', 'format', 'out', 'compare', 'confirm',
        'watch', 'history', 'explain', 'plan', 'validate', 'is-active', 'is-enabled', 'list-units'}
MUTATE = {'add', 'set', 'create', 'apply', 'put', 'update', 'edit', 'enable', 'attach', 'insert',
          'install', 'patch', 'modify', 'new', 'append', 'write', 'import', 'configure', 'config',
          'grant', 'chmod', 'chown', 'chgrp', 'tee', 'mv', 'cp', 'ln', 'mkdir', 'touch', 'move', 'copy',
          'rename', 'replace', 'register', 'tag', 'push', 'commit', 'save', 'restore', 'load', 'mount',
          'assign', 'allow', 'accept', 'open', 'scale', 'rollout', 'label', 'annotate', 'taint',
          'reload', 'restart', 'daemon-reload', 'unmask', 'sed', 'dd', 'mkfs', 'useradd', 'usermod',
          'passwd', 'login', 'join', 'upgrade', 'build', 'init'}
DELETE = {'delete', 'del', 'remove', 'rm', 'rmdir', 'purge', 'drop', 'destroy', 'uninstall', 'truncate',
          'wipe', 'flush', 'clear', 'erase', 'kill', 'pkill', 'killall', 'stop', 'disable', 'detach',
          'revoke', 'prune', 'reset', 'mask', 'unregister', 'deny', 'reject', 'shred', 'unlink',
          'deregister', 'terminate', 'shutdown', 'halt', 'poweroff', 'reboot', 'userdel', 'cordon',
          'drain', 'evict', 'zap', 'clean', 'format-volume'}
EXEC = {'exec', 'run', 'invoke', 'start', 'call', 'eval', 'ssh', 'shell', 'source', 'spawn', 'submit',
        'execute', 'start-process', 'iex', 'invoke-expression', 'invoke-command'}
CLASS_OF = [('DELETE', DELETE), ('EXEC', EXEC), ('MUTATE', MUTATE), ('READ', READ)]

FLAG_VERB = re.compile(r'^--?(add|remove|delete|del|list|get|set|query|zap|flush|enable|disable|'
                       r'insert|append|new|change|reload|permanent|state|info|show|clear|reset)\b', re.I)
BOOLISH = {'true', 'false', 'yes', 'no', 'on', 'off', 'enable', 'enabled', 'disable', 'disabled',
           'start', 'stop', 'allow', 'deny', 'accept', 'drop', 'reject', 'none', 'all', 'any'}
SMALL_INT = re.compile(r'^-?\d{1,2}$')
VALUE_FLAG = re.compile(r'^(--?[A-Za-z][\w-]*|/[A-Za-z])$')
KEY_VALUE = re.compile(r'^([A-Za-z_][\w.-]{0,40})[:=]([^=\s]+)$')

TARGETS = [
    ('ROOT', re.compile(r'^(/|/\*|[A-Za-z]:\\?|[A-Za-z]:\\\*|~|\$HOME|\$\{HOME\})/?$')),
    ('SECRET', re.compile(r'(^|[/\\])(\.ssh|\.aws|\.kube|\.gnupg|\.docker|\.netrc|\.git-credentials|'
                          r'\.pgpass|\.npmrc|\.pypirc|\.env(\.\w+)?|credentials|id_[a-z0-9]+|'
                          r'shadow|gshadow|sudoers(\.d)?|SAM|SECURITY|SYSTEM)([/\\]|$)', re.I)),
    ('SYSTEM', re.compile(r'^(/(etc|usr|bin|sbin|boot|lib|lib64|sys|proc|dev|var/log|root)(/|$)|'
                          r'[A-Za-z]:\\(Windows|Program Files)|HK(LM|EY_LOCAL_MACHINE)|HKCU|HKEY_CURRENT_USER)', re.I)),
    ('SERVICE', re.compile(r'^/(var/lib|var/cache|var/spool|var/run|run|srv|opt|mnt|data)(/|$)')),
    ('TMP', re.compile(r'^(/tmp|/var/tmp|\$TMPDIR|\$\{TMPDIR\}|%TEMP%|\$env:TEMP|[A-Za-z]:\\Temp)(/|\\|$)', re.I)),
    ('HOME', re.compile(r'^(~|\$HOME|/home/[^/]+|/Users/[^/]+)(/|$)')),
]
PATHLIKE = re.compile(r'^([/~$.]|[A-Za-z]:\\|HK(LM|CU|EY_)|[\w.-]+/)')
# Heads whose plain (non-flag) arguments are file paths, so `rm -rf dist` targets the project.
FILE_HEADS = {'rm', 'rmdir', 'mv', 'cp', 'chmod', 'chown', 'chgrp', 'ln', 'touch', 'mkdir', 'shred',
              'truncate', 'tee', 'unlink', 'cat', 'ls', 'stat', 'head', 'tail', 'del', 'rd', 'remove-item',
              'copy-item', 'move-item', 'get-content', 'set-content'}


def segments(text):
    """Command segments as lists of raw words (quotes stripped), split on shell separators."""
    toks = re.findall(r'\n|' + tokens.__globals__['TOKEN'].pattern, mask_heredocs(text))
    seg = []
    for t in toks:
        if t in SEPARATORS or t.startswith('#'):
            if seg:
                yield seg
            seg = []
            continue
        if t in ('<', '>', '>>') or re.fullmatch(r'\d*>&\d*', t):
            continue
        seg.append(t[1:-1] if t[:1] in '\'"' and t[-1:] == t[:1] and len(t) > 1 else t)
    if seg:
        yield seg


def base(word):
    return re.split(r'[\\/]', word)[-1].lower()


def head_and_rest(seg):
    i = 0
    while i < len(seg) and (base(seg[i]) in PREFIXES or re.fullmatch(r'[A-Za-z_]\w*=.*', seg[i])
                            or (i and seg[i].startswith('-'))):
        i += 1
    return (base(seg[i]), seg[i + 1:]) if i < len(seg) else (None, [])


def verb_class(head, rest):
    """Class of what the segment does. PowerShell Verb-Noun, hyphenated subcommands
    (aws iam list-users), plain subcommands (kubectl delete) and verb flags (--add-port)."""
    candidates = []
    if '-' in head and head.split('-', 1)[0] in READ | MUTATE | DELETE | EXEC:
        candidates.append(head.split('-', 1)[0])           # Get-Item, Remove-Item, Set-MpPreference
    candidates.append(head)
    words = [w for w in rest if not w.startswith('-')][:2]
    for w in words:
        lw = w.lower()
        candidates += [lw, lw.split('-', 1)[0]]
    for w in rest:
        m = FLAG_VERB.match(w)
        if m:
            candidates.append(m.group(1).lower())
    for name, vocab in CLASS_OF:
        if any(c in vocab for c in candidates):
            return name
    return None


def target_class(word, file_head=False):
    w = word.strip()
    if not w or w.startswith('-'):
        return None
    for name, rx in TARGETS:
        if rx.search(w) if name == 'SECRET' else rx.match(w):
            return name
    if PATHLIKE.match(w) or (file_head and re.fullmatch(r'[\w.*@+-][\w.*@+/-]*', w)):
        return 'PROJECT'
    return None


def values(rest):
    out = []
    for k, w in enumerate(rest):
        lw = w.lower()
        m = KEY_VALUE.match(w)
        if m and (SMALL_INT.match(m.group(2)) or m.group(2).lower() in BOOLISH):
            out += ['VAL=' + m.group(2).lower(), m.group(1).lower() + '=' + m.group(2).lower()]
        elif k and VALUE_FLAG.match(rest[k - 1]) and (SMALL_INT.match(w) or lw in BOOLISH):
            out += ['VAL=' + lw, rest[k - 1].lower() + '=' + lw]
    return out


def action_markers(text):
    found = set()
    for seg in segments(text):
        head, rest = head_and_rest(seg)
        if head is None:
            continue
        vc = verb_class(head, rest)
        if vc:
            found.update(['VERB=' + vc, head + ':' + vc])
        for w in rest:
            tc = target_class(w, head in FILE_HEADS)
            if tc:
                found.add('TGT=' + tc)
                if vc:
                    found.add(vc + '@' + tc)
        found.update(values(rest))
    return sorted(found)
