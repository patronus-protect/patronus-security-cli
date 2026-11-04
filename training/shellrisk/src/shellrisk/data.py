"""Input data: frozen JSONL files outside the repository, verified against data/manifest.json.

The data directory is $SHELLRISK_DATA, or training/shellrisk/.data/v1 by default. Small files that we
authored or relabelled (DefenseClaw relabels, review decisions) live in the repository under data/.
"""
import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[2]
REPO_DATA = PACKAGE_ROOT / 'data'
MANIFEST = REPO_DATA / 'manifest.json'
MODELS = PACKAGE_ROOT / 'models'


def data_dir():
    return Path(os.environ.get('SHELLRISK_DATA', PACKAGE_ROOT / '.data' / 'v1'))


def path(name):
    """Path of one frozen input; raises if it is missing or its sha256 differs from the manifest."""
    p = data_dir() / name
    want = json.loads(MANIFEST.read_text())['files'][name]['sha256']
    if not p.exists():
        raise FileNotFoundError(f'{p} is missing; see training/shellrisk/README.md, "Data"')
    _verify(str(p), want)
    return p


@lru_cache(maxsize=None)
def _verify(p, want):
    h = hashlib.sha256()
    with open(p, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    if h.hexdigest() != want:
        raise ValueError(f'{p}: sha256 {h.hexdigest()} does not match data/manifest.json')


def jsonl(p):
    with open(p, encoding='utf-8') as f:
        return [json.loads(line) for line in f]


def rows(name):
    return jsonl(path(name))


def repo_rows(name):
    return jsonl(REPO_DATA / name)


def fingerprint(text):
    """Whitespace-insensitive identity of a command, used for de-duplication across all sources."""
    return hashlib.sha256(' '.join(text.split()).encode()).hexdigest()
