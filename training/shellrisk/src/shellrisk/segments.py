"""Fact extractor for the Cedar rule member: per-segment facts plus whole-command pattern hits.

Deterministic and portable (Python reference for the Rust port). Text is never executed.
Each segment becomes one Cedar request with context
  program   command head, lowercased, without directory and .exe
  ops       approximate DefenseClaw OperationKind names derived from our verb/target/relation facts
  patterns  ids of the bundle's named regex patterns that match the whole command text
The op mapping is an approximation of DefenseClaw's semantic layer, documented in OPS.
"""
import re

from .markers import FILE_HEADS, target_class, verb_class

DOWNLOADERS = {'curl', 'wget', 'iwr', 'irm', 'invoke-webrequest', 'invoke-restmethod', 'aria2c', 'fetch',
               'bitsadmin', 'start-bitstransfer'}
DECODERS = {'base64', 'xxd', 'certutil', 'openssl', 'uudecode', 'gunzip', 'zcat', 'base32'}
CONNECTORS = {'nc', 'ncat', 'netcat', 'socat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync', 'ftp', 'tftp'}
PERMISSION = {'chmod', 'chown', 'chgrp', 'icacls', 'cacls', 'takeown', 'setfacl', 'usermod', 'gpasswd',
              'visudo', 'set-acl', 'chattr'}
PRIVILEGE = {'sudo', 'doas', 'su', 'runas', 'pkexec', 'start-process'}
COPIERS = {'cp', 'mv', 'rsync', 'scp', 'copy', 'xcopy', 'robocopy', 'copy-item', 'move-item', 'install'}
DISK_WRITERS = {'dd', 'mkfs', 'fdisk', 'parted', 'sfdisk', 'wipefs', 'diskpart', 'format', 'format-volume',
                'clear-disk', 'blkdiscard', 'shred'}
CONTAINER = {'docker', 'podman', 'nerdctl', 'ctr', 'kubectl', 'crictl'}
KILLERS = {'kill', 'pkill', 'killall', 'taskkill', 'stop-process', 'skill'}
ACCOUNTS = {'useradd', 'adduser', 'usermod', 'userdel', 'passwd', 'chpasswd', 'new-localuser',
            'set-localuser', 'add-localgroupmember', 'dscl', 'sysadminctl'}
SCANNERS = {'nmap', 'masscan', 'zmap', 'rustscan', 'arp-scan', 'nbtscan'}
UPLOAD_FLAGS = re.compile(r'^(-d|--data(-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file(=.*)?|'
                          r'--post-data(=.*)?|-InFile|-Body)$', re.I)

# DefenseClaw OperationKind -> how we approximate it from our facts
OPS = {
    'READ': 'verb class READ',
    'DELETE': 'verb class DELETE',
    'CONFIG_CHANGE': 'verb class MUTATE',
    'PERMISSION_CHANGE': 'head in PERMISSION',
    'CREDENTIAL_READ': 'any argument with target class SECRET',
    'FETCH': 'head in DOWNLOADERS or a DL-> relation in the command',
    'DECODE': 'head in DECODERS',
    'CONNECT': 'head in CONNECTORS',
    'LISTEN': 'head in CONNECTORS with a -l/--listen flag',
    'EXECUTE': 'verb class EXEC',
    'WRITE': 'verb class MUTATE or a > / >> redirect in the segment',
    'PRIVILEGE': 'segment prefixed with sudo/doas or head in PRIVILEGE',
    'UPLOAD': 'downloader head with an upload flag (-d, -F, -T, --post-file, -InFile, -Body), or scp/rsync',
    'DISK_WRITE': 'head in DISK_WRITERS',
    'COPY': 'head in COPIERS',
    'CONTAINER_RUN': 'head in CONTAINER with run/exec/create subcommand',
    'PROCESS_KILL': 'head in KILLERS',
    'ACCOUNT_CHANGE': 'head in ACCOUNTS',
    'NETWORK_SCAN': 'head in SCANNERS',
}


def program(head):
    return re.sub(r'\.exe$', '', head or '')


_UNSET = object()


def segment_ops(seg, head, rest, redirected, rel, vc=_UNSET):
    """OperationKinds of one segment (seg = raw words, head/rest from head_and_rest, rel = relations(text)).
    vc overrides the verb class (the facts extractor passes the vocabulary verb)."""
    prog = program(head)
    if vc is _UNSET:
        vc = verb_class(head, rest)
    tcs = {target_class(w, head in FILE_HEADS) for w in rest} - {None}
    ops = set()
    ops |= {'READ'} if vc == 'READ' else set()
    ops |= {'DELETE'} if vc == 'DELETE' else set()
    ops |= {'CONFIG_CHANGE'} if vc == 'MUTATE' else set()
    ops |= {'EXECUTE'} if vc == 'EXEC' else set()
    ops |= {'PERMISSION_CHANGE'} if prog in PERMISSION else set()
    ops |= {'CREDENTIAL_READ'} if 'SECRET' in tcs else set()
    ops |= {'FETCH'} if prog in DOWNLOADERS or any(r.startswith('DL->') for r in rel) else set()
    ops |= {'DECODE'} if prog in DECODERS else set()
    if prog in CONNECTORS:
        ops.add('LISTEN' if any(w in ('-l', '--listen', '-lvnp', '-lnvp', '-nlvp') for w in rest) else 'CONNECT')
    if vc == 'MUTATE' or redirected:
        ops.add('WRITE')
    if prog in PRIVILEGE or (seg and seg[0].rsplit('/', 1)[-1].lower() in ('sudo', 'doas')):
        ops.add('PRIVILEGE')
    if (prog in DOWNLOADERS and any(UPLOAD_FLAGS.match(w) for w in rest)) or prog in ('scp', 'rsync'):
        ops.add('UPLOAD')
    ops |= {'DISK_WRITE'} if prog in DISK_WRITERS or prog.startswith('mkfs') else set()
    ops |= {'COPY'} if prog in COPIERS else set()
    if prog in CONTAINER and any(w.lower() in ('run', 'exec', 'create') for w in rest[:2]):
        ops.add('CONTAINER_RUN')
    ops |= {'PROCESS_KILL'} if prog in KILLERS else set()
    ops |= {'ACCOUNT_CHANGE'} if prog in ACCOUNTS else set()
    ops |= {'NETWORK_SCAN'} if prog in SCANNERS else set()
    return sorted(ops)
