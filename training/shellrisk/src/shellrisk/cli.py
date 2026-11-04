"""shellrisk command line. Text is only ever parsed and scored, never executed.

  shellrisk score "rm -rf ~" [--model DIR] [--json] [--context '{"cwd": ...}']
  shellrisk train configs/k26.toml            # fit, save models/<name>/, run all gates
  shellrisk gates --model models/k26          # re-run the gates of a saved model
  shellrisk holdout --model models/k26        # agent-holdout gate against G
  shellrisk holdout-fetch RAW_DIR OUT.jsonl   # rebuild the agent holdout input
  shellrisk data verify                       # check every frozen input against data/manifest.json
"""
import argparse
import json
import sys
import tomllib
from pathlib import Path

from . import data


def _corpus_and_cfg(model_dir):
    from . import corpus
    cfg = json.loads((Path(model_dir) / 'config.json').read_text())
    return corpus.load(cfg), cfg


def _reference_g():
    from .model import load_reference_g
    data.path('reference_g/model.json'); data.path('reference_g/shell_tokens.py')
    return load_reference_g(data.data_dir() / 'reference_g')


def cmd_score(a):
    from .facts.schema import dumps
    from .verdict import Bundle
    b = Bundle.load(a.model)
    for command in a.command or [line.rstrip('\n') for line in sys.stdin]:
        v = b.score(command, context=json.loads(a.context) if a.context else None)
        if a.json:
            print(dumps(v))
            continue
        print(f"{v['decision']:5}  {command}")
        print(f"       score {v['score']:.2f}   (ask above {v['cuts']['ask']:.2f}, block above {v['cuts']['block']:.2f})")
        m = v['model']
        print(f"       model {m['decision']} at {m['score']:.2f}; strongest features: "
              + ', '.join(f"{f['feature']} {f['weight']:+.2f}" for f in m['top_features'][:3]))
        for p in v['policies']:
            print(f"       policy {p['id']} ({p['tier']}, {p['decision']}, {', '.join(p['where'])}): {p['title']}")


def _gates(name, model, corpus, out_dir):
    from . import gates
    rep = gates.run(name, model, _reference_g(), corpus)
    (out_dir / 'gates.json').write_text(json.dumps(rep, indent=1, default=float))
    text = gates.format_report(rep)
    (out_dir / 'gates.txt').write_text(text + '\n')
    print(text)
    return rep


def cmd_train(a):
    from . import corpus, train
    cfg = tomllib.loads(Path(a.config).read_text())
    out = Path(a.out or data.MODELS / cfg['name'])
    out.mkdir(parents=True, exist_ok=True)
    c = corpus.load(cfg)
    model, info = train.fit(cfg, c)
    model.meta = {'name': cfg['name'], 'training': info}
    model.save(out / 'model.json')
    (out / 'config.json').write_text(json.dumps(cfg, indent=1) + '\n')
    print(f"trained {cfg['name']}: C={info['C']}, {info['features']} features, {info['fit_rows']} fit rows, "
          f"{info['fit_seconds']} s -> {out}")
    rep = _gates(cfg['name'], model, c, out)
    sys.exit(0 if rep['passed'] else 1)


def cmd_gates(a):
    from .model import LinearModel
    c, cfg = _corpus_and_cfg(a.model)
    rep = _gates(cfg['name'], LinearModel.load(Path(a.model) / 'model.json'), c, Path(a.model))
    sys.exit(0 if rep['passed'] else 1)


def cmd_holdout(a):
    from .holdout import evaluate
    from .model import LinearModel
    from .verdict import Bundle
    models, c = {'G': _reference_g()}, None
    for d in a.model:
        c, cfg = _corpus_and_cfg(d)
        models[cfg['name']] = LinearModel.load(Path(d) / 'model.json')
    # G is scored with the first candidate's gated policies, so only the models differ
    rep = evaluate.run(models, Bundle.load(a.model[0]).rules, c)
    out = Path(a.model[-1])
    (out / 'holdout.json').write_text(json.dumps(rep, indent=1, default=float))
    evaluate.write_review(rep, out / 'holdout_review.csv')
    print(evaluate.format_report(rep))
    print(f'\nreview sheet: {out / "holdout_review.csv"} ({len(rep["review"])} flagged rows)')
    sys.exit(0 if all(g['ok'] for g in rep['gate'].values()) else 1)


def cmd_fetch(a):
    from .holdout import fetch
    print(f'wrote {fetch.fetch(a.raw_dir, a.out)} commands to {a.out}')


def cmd_data(a):
    m = json.loads(data.MANIFEST.read_text())['files']
    bad = 0
    for name in m:
        try:
            data.path(name); print(f'ok       {name}')
        except (FileNotFoundError, ValueError) as e:
            bad += 1; print(f'PROBLEM  {name}: {e}')
    sys.exit(1 if bad else 0)


def main(argv=None):
    p = argparse.ArgumentParser(prog='shellrisk', description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('score', help='verdict for one or more commands (stdin if none given)')
    s.add_argument('command', nargs='*'); s.add_argument('--model'); s.add_argument('--json', action='store_true')
    s.add_argument('--context', help='JSON: cwd, home, repo_root, dialect')
    s.set_defaults(fn=cmd_score)
    s = sub.add_parser('train', help='fit a candidate from a TOML config and run all gates')
    s.add_argument('config'); s.add_argument('--out'); s.set_defaults(fn=cmd_train)
    s = sub.add_parser('gates', help='re-run the release gates of a saved model')
    s.add_argument('--model', required=True); s.set_defaults(fn=cmd_gates)
    s = sub.add_parser('holdout', help='agent-holdout gate of one or more saved models against G')
    s.add_argument('--model', action='append', required=True); s.set_defaults(fn=cmd_holdout)
    s = sub.add_parser('holdout-fetch', help='rebuild the agent-holdout input from Hugging Face')
    s.add_argument('raw_dir'); s.add_argument('out'); s.set_defaults(fn=cmd_fetch)
    s = sub.add_parser('data', help='verify the frozen inputs')
    s.add_argument('action', choices=['verify']); s.set_defaults(fn=cmd_data)
    a = p.parse_args(argv)
    a.fn(a)


if __name__ == '__main__':
    main()
