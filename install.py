#!/usr/bin/env python3
"""Install a verified public Patronus Security CLI release (standard-library Python only)."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tempfile
import urllib.request
import zipfile

REPOSITORY = "patronus-protect/patronus-security-cli"
INSTALLER_VERSION = "0.1.1"

def fetch(url, limit):
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "patronus-installer"}
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=180) as response:
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Release exceeds size limit")
    return data

def platform_target():
    machine = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    suffix = {"Darwin": "apple-darwin", "Linux": "unknown-linux-gnu"}.get(platform.system())
    supported = (platform.system() == "Darwin" and machine in {"aarch64", "x86_64"}) or (platform.system() == "Linux" and machine == "x86_64")
    if not suffix or not supported:
        raise ValueError("No prebuilt release is available for this platform")
    return f"{machine}-{suffix}"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-onboarding", action="store_true", help="Install only; do not start interactive setup")
    parser.add_argument("--archive", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--checksum", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--version", help=argparse.SUPPRESS)
    parser.add_argument("--install-dir", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.archive:
        if not args.checksum or not args.version:
            raise ValueError("Local installation requires --archive, --checksum and --version")
        version = args.version.removeprefix("v")
    else:
        version = (args.version or INSTALLER_VERSION).removeprefix("v")
    if not version or len(version) > 64 or any(not (c.isascii() and (c.isalnum() or c in ".-")) for c in version):
        raise ValueError("Invalid release version")
    release = None
    if not args.archive:
        release = json.loads(fetch(f"https://api.github.com/repos/{REPOSITORY}/releases/tags/v{version}", 1024 * 1024))
        if release["tag_name"] != f"v{version}":
            raise ValueError("Release version mismatch")
    name = f"patronus-security-scanner-{version}-{platform_target()}.zip"
    if args.archive:
        if args.archive.name != name or args.archive.stat().st_size > 250 * 1024 * 1024 or args.checksum.stat().st_size > 4096:
            raise ValueError("Invalid local release artifact")
        data = args.archive.read_bytes()
        checksum = args.checksum.read_text(encoding="ascii").split()[0]
    else:
        def artifact(filename, limit):
            entry = next(a for a in release["assets"] if a["name"] == filename)
            url = entry["browser_download_url"]
            if not url.startswith(f"https://github.com/{REPOSITORY}/releases/download/"):
                raise ValueError("Untrusted release URL")
            return fetch(url, limit)
        checksum = artifact(name + ".sha256", 4096).decode("ascii").split()[0]
        data = artifact(name, 250 * 1024 * 1024)
    if len(checksum) != 64 or hashlib.sha256(data).hexdigest() != checksum.lower():
        raise ValueError("Release checksum mismatch; installation unchanged")
    directory = args.install_dir or Path.home() / ".local/bin"
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / "patronus-security-scanner"
    if target.is_symlink():
        raise ValueError("Use the installer that owns the existing CLI symlink")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = [item for item in archive.infolist() if item.filename == target.name]
        if len(entries) != 1 or entries[0].file_size > 250 * 1024 * 1024 or (entries[0].external_attr >> 16) & 0o170000 == 0o120000:
            raise ValueError("Invalid executable entry")
        binary = archive.read(entries[0])
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".patronus-install-", dir=directory, delete=False) as out:
            temporary = Path(out.name)
            out.write(binary)
            out.flush()
            os.fsync(out.fileno())
        temporary.chmod(0o755)
        subprocess.run([str(temporary), "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        os.replace(temporary, target)
    finally:
        if temporary and temporary.exists():
            temporary.unlink()
    print(f"Installed Patronus {version}: {target}")
    if str(directory) not in os.environ.get("PATH", "").split(os.pathsep):
        print(f'Add this directory to PATH: {directory}')
    if not args.no_onboarding:
        if not sys.stdin.isatty():
            try:
                terminal = os.open("/dev/tty", os.O_RDWR)
                for descriptor in (0, 1, 2):
                    os.dup2(terminal, descriptor)
                os.close(terminal)
            except OSError:
                raise ValueError("Installation succeeded, but onboarding needs an interactive terminal; rerun patronus-security-scanner onboarding")
        os.execv(target, [str(target), "onboarding"])
    print(f"Start setup later: {target} onboarding")

if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, StopIteration, subprocess.SubprocessError, zipfile.BadZipFile):
        sys.exit("Patronus installation failed. Check that the public release and matching checksum artifacts are published. Existing installations were preserved unless replacement already completed.")
