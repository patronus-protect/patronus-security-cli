import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

INSTALL_SH = Path(__file__).resolve().parents[1] / 'install.sh'
spec = importlib.util.spec_from_file_location('installer', Path(__file__).resolve().parents[1] / 'install.py')
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class InstallerTest(unittest.TestCase):
    def test_shell_entrypoint_verifies_and_runs_the_backend(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            backend = root / 'install.py'
            marker = root / 'called'
            backend.write_text("import os, pathlib, sys\npathlib.Path(os.environ['MARKER']).write_text(' '.join(sys.argv[1:]))\n")
            (root / 'install.py.sha256').write_text(hashlib.sha256(backend.read_bytes()).hexdigest())
            environment = {**os.environ, 'PATRONUS_INSTALLER_BASE_URL': root.as_uri(), 'MARKER': str(marker)}
            subprocess.run(['sh', str(INSTALL_SH), '--no-onboarding'], check=True, env=environment)
            self.assertEqual(marker.read_text(), '--no-onboarding')

    def test_linux_arm64_is_not_advertised_without_a_release_target(self):
        with patch.object(platform, 'system', return_value='Linux'), patch.object(platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(ValueError, 'No prebuilt release'):
                installer.platform_target()

    def install(self, home, *, mismatch=False, health_fails=False, entry='patronus-security-scanner', onboarding=False):
        content = io.BytesIO()
        with zipfile.ZipFile(content, 'w') as archive:
            archive.writestr(entry, b'new verified executable')
        payload = content.getvalue()
        name = 'patronus-security-scanner-0.1.0-aarch64-apple-darwin.zip'
        base = f'https://github.com/{installer.REPOSITORY}/releases/download/v0.1.0/'
        release = {'tag_name': 'v0.1.0', 'assets': [{'name': f, 'browser_download_url': base + f} for f in [name, name + '.sha256']]}
        def fetch(url, limit):
            if url.endswith('/latest'): return json.dumps(release).encode()
            if url.endswith('.sha256'): return (('0' * 64) if mismatch else hashlib.sha256(payload).hexdigest()).encode()
            return payload
        argv = ['install.py'] if onboarding else ['install.py', '--no-onboarding']
        with patch.object(installer.Path, 'home', return_value=home), patch.object(installer, 'fetch', side_effect=fetch), patch.object(installer, 'platform_target', return_value='aarch64-apple-darwin'), patch.object(installer.sys, 'argv', argv), patch.object(installer.subprocess, 'run', side_effect=subprocess.CalledProcessError(1, 'version') if health_fails else None), patch('builtins.print'):
            installer.main()

    def test_verified_release_replaces_existing_cli(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            self.install(home)
            self.assertEqual((home / '.local/bin/patronus-security-scanner').read_bytes(), b'new verified executable')

    def test_failed_checks_preserve_previous_installation(self):
        for options in [{'mismatch': True}, {'health_fails': True}, {'entry': '../patronus-security-scanner'}]:
            with self.subTest(options=options), tempfile.TemporaryDirectory() as root:
                home = Path(root)
                target = home / '.local/bin/patronus-security-scanner'
                target.parent.mkdir(parents=True)
                target.write_bytes(b'previous installation')
                with self.assertRaises((ValueError, subprocess.SubprocessError)):
                    self.install(home, **options)
                self.assertEqual(target.read_bytes(), b'previous installation')
                self.assertEqual(list(target.parent.iterdir()), [target])

    def test_existing_symlink_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            target = home / '.local/bin/patronus-security-scanner'
            target.parent.mkdir(parents=True)
            target.symlink_to(home / 'other-manager')
            with self.assertRaises(ValueError): self.install(home)
            self.assertTrue(target.is_symlink())

    def test_onboarding_starts_by_default(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root)
            with patch.object(installer.sys.stdin, 'isatty', return_value=True), patch.object(installer.os, 'execv') as execute:
                self.install(home, onboarding=True)
            target = home / '.local/bin/patronus-security-scanner'
            execute.assert_called_once_with(target, [str(target), 'onboarding'])

    def test_local_release_archive_uses_the_same_verification_path(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            archive = root / 'patronus-security-scanner-0.1.0-aarch64-apple-darwin.zip'
            content = io.BytesIO()
            with zipfile.ZipFile(content, 'w') as bundle:
                bundle.writestr('patronus-security-scanner', b'local verified executable')
            archive.write_bytes(content.getvalue())
            checksum = root / 'archive.sha256'
            checksum.write_text(hashlib.sha256(content.getvalue()).hexdigest())
            install_dir = root / 'bin'
            argv = ['install.py', '--archive', str(archive), '--checksum', str(checksum), '--version', '0.1.0', '--install-dir', str(install_dir), '--no-onboarding']
            with patch.object(installer, 'platform_target', return_value='aarch64-apple-darwin'), patch.object(installer.sys, 'argv', argv), patch.object(installer.subprocess, 'run'), patch('builtins.print'):
                installer.main()
            self.assertEqual((install_dir / 'patronus-security-scanner').read_bytes(), b'local verified executable')

if __name__ == '__main__':
    unittest.main()
