"""Freeze the training and evaluation inputs of the shell-risk experiments into versioned JSONL files.

Provenance record, not part of the package: this ran once against the research workspace
(benchmark/shellrisk-*, gitignored) and the Hugging Face cache. It calls the original loaders and writes
their outputs unchanged, so the package reads plain rows instead of rebuilding them from eight old
benchmark folders. The frozen files are listed with sha256 in data/manifest.json.

Run (research workspace only):
  Patronus-Datasets/.venv/bin/python -I training/shellrisk/tools/freeze_inputs.py OUT_DIR
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
WS = REPO / 'benchmark' / 'shellrisk-ensemble-2026-11-03'
OUT = Path(sys.argv[1])
sys.argv[1:] = []  # eval_extra parses sys.argv on import
sys.path[:0] = [str(WS / 'k'), str(WS / 'h'), str(WS / 'f')]

import run_h  # noqa: E402
import run_k  # noqa: E402
import retrain159  # noqa: E402
import probes  # noqa: E402


def write(name, rows):
    p = OUT / name
    with p.open('w') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + '\n')
    return p


def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    files = {}
    data, _ = retrain159.load_data(run_h.B159 / 'corpus_159g.json')
    files['corpus.jsonl'] = write('corpus.jsonl', [dict(r, split=s) for s in ('fit', 'val', 'test') for r in data[s][1]])
    # run_h.new_rows() must run exactly once per process, as in the original runs: secjudge_eval samples
    # nl2bash with a module-level random.Random(13), so a second call draws a different sample
    cfg = dict(run_k.DEFAULTS, aug=False, dc=True)
    d, it, eo, dc_test = run_k.load(cfg)
    infra = run_k._CACHE['base'][1]
    files['infraset_pool.jsonl'] = write('infraset_pool.jsonl', infra)

    # every evaluation set, unfiltered; the training-overlap filter on the R: sets is applied per run
    S = {}
    S.update(run_k.sets_for(d, it, eo, dc_test))
    for name, rows in run_k.robustness_sets().items():
        S['R:' + name] = ([t for t, _ in rows], [y for _, y in rows])
    S['secret_exfil_probes'] = ([r['text'] for r in probes.rows()], [1] * len(probes.rows()))
    files['evalsets.jsonl'] = write('evalsets.jsonl', [{'set': n, 'text': t, 'label': int(y)}
                                                       for n, (ts, ys) in S.items() for t, y in zip(ts, ys)])
    fx = retrain159.fixture_rows()
    files['fixtures_159.jsonl'] = write('fixtures_159.jsonl', fx)
    files['agent_holdout.jsonl'] = OUT / 'agent_holdout.jsonl'
    shutil.copy(WS / 'k' / 'data' / 'agent_holdout.jsonl', files['agent_holdout.jsonl'])
    ref = OUT / 'reference_g'
    shutil.copytree(run_h.B159 / 'release_159g', ref, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
    for p in sorted(x for x in ref.iterdir() if x.is_file()):
        files[f'reference_g/{p.name}'] = p
    manifest = {n: {'sha256': sha(p), 'bytes': p.stat().st_size} for n, p in files.items()}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=1, sort_keys=True) + '\n')
    print(json.dumps({n: v['bytes'] for n, v in manifest.items()}, indent=1))


if __name__ == '__main__':
    main()
