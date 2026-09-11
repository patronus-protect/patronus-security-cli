#!/bin/sh
set -eu

repository=${PATRONUS_GITHUB_REPOSITORY:-patronus-protect/patronus-security-cli}
version=${PATRONUS_VERSION:-0.1.0}
version=${version#v}
case "$version" in
  *[!0-9A-Za-z.-]*|'') echo "Invalid release version" >&2; exit 1 ;;
esac
[ "${#version}" -le 64 ] || { echo "Invalid release version" >&2; exit 1; }
base_url=${PATRONUS_INSTALLER_BASE_URL:-https://github.com/$repository/releases/download/v$version}
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/patronus-installer.XXXXXX")
trap 'rm -rf "$work_dir"' 0 HUP INT TERM

download() {
  if [ -n "${GH_TOKEN:-${GITHUB_TOKEN:-}}" ]; then
    token=${GH_TOKEN:-$GITHUB_TOKEN}
    curl -fsSL -H "Authorization: Bearer $token" "$1" -o "$2"
  else
    curl -fsSL "$1" -o "$2"
  fi
}

download "$base_url/install.py" "$work_dir/install.py"
download "$base_url/install.py.sha256" "$work_dir/install.py.sha256"

expected=$(awk 'NR == 1 { print $1 }' "$work_dir/install.py.sha256")
case "$expected" in
  *[!0-9A-Fa-f]*|'') echo "Invalid installer checksum" >&2; exit 1 ;;
esac
[ "${#expected}" -eq 64 ] || { echo "Invalid installer checksum" >&2; exit 1; }
if command -v shasum >/dev/null 2>&1; then
  actual=$(shasum -a 256 "$work_dir/install.py" | awk '{ print $1 }')
elif command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$work_dir/install.py" | awk '{ print $1 }')
else
  echo "A SHA-256 tool (shasum or sha256sum) is required" >&2
  exit 1
fi
[ "$actual" = "$expected" ] || { echo "Installer checksum mismatch" >&2; exit 1; }

python3 "$work_dir/install.py" "$@" --version "$version"
