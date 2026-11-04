"""Patronus core policies over patronus.facts/1 (tier `core`). No regex: every condition reads facts only.

Same record shape as the translated DefenseClaw rules; `cap` is the strongest level, the val gate in
policies/gate.gate decides block / ask / rejected.
"""


def _p(pid, cap, scope, title, condition):
    return {'id': 'core.' + pid, 'tier': 'core', 'cap': cap, 'scope': scope, 'title': title, 'condition': condition,
            'pattern': None, 'bucket': 'own', 'status': 'translated'}


POLICIES = [
    _p('secret_to_net', 'block', 'command', 'Sends secret material (keys, cloud credentials, .env, ...) to the network',
       'context.flows.contains("SECRET>NET")'),
    _p('cred_literal_to_net', 'block', 'command', 'Sends a literal credential (token, key) to a network tool',
       'context.flows.contains("CRED_LITERAL>NET")'),
    _p('remote_to_exec', 'block', 'command', 'Runs code fetched from the network (pipe, substitution or saved file)',
       'context.flows.containsAny(["REMOTE>INTERP", "REMOTE>EXEC"])'),
    _p('db_dump_to_net', 'block', 'command', 'Sends a database dump to the network',
       'context.flows.contains("DB_DUMP>NET")'),
    _p('sql_exec', 'block', 'segment', 'Runs OS code or files through SQL (UDF SONAME, INTO OUTFILE, COPY PROGRAM, ...)',
       'context.sql.contains("SQL_EXEC")'),
    _p('decoded_to_interp', 'block', 'command', 'Decodes data and pipes it into an interpreter',
       'context.flows.contains("DECODED>INTERP")'),
    _p('secctl_off', 'block', 'segment', 'Turns off a security control (audit, AV/EDR, firewall, SELinux, ...)',
       'context.settings.contains("SECCTL:OFF")'),
    _p('sudoers_nopasswd_all', 'block', 'segment', 'Grants passwordless sudo for all commands',
       'context.grants.contains("ALL")'),
    _p('host_root_mount', 'block', 'segment', 'Mounts the host root filesystem into a container',
       'context.host_root_mount'),
    _p('privileged_container', 'ask', 'segment', 'Starts a privileged container',
       'context.privileged && context.ops.contains("CONTAINER_RUN")'),
    _p('metadata_fetch', 'block', 'segment', 'Fetches from a link-local address (cloud instance metadata)',
       'context.ops.containsAny(["FETCH", "CONNECT"]) && context.net_scopes.contains("LINK_LOCAL")'),
    _p('persistence_write', 'ask', 'segment', 'Writes a persistence location (shell profile, cron, authorized_keys, ...)',
       'context.objects.containsAny(["WRITE@PERSIST", "APPEND@PERSIST"])'),
    _p('git_exec_config', 'ask', 'command', 'Sets git config that executes commands (hooks, sshCommand, fsmonitor, ...)',
       'context.objects.contains("GIT_EXEC_CONFIG")'),
]
