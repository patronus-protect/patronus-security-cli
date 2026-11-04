"""Fetch a fresh agent-command holdout (inert text, never executed, never used for training).

Sources (both published after our training data, Apache-2.0):
  ai-and/termgrade-trajectories       Terminus-2 episodes, 6 models, 1,004 tasks; commands = keystrokes per turn
  harithoppil/terminal-bench-2-...    Terminal-Bench 2 leaderboard runs; only final responses, few commands
TermGrade: one random parquet row group per model file via HTTP range reads (no full download); the TB2 jsonl
(39 MB) is read from a local copy in raw_dir if present. Only the extracted commands are written.

Run: shellrisk holdout-fetch RAW_DIR OUT.jsonl   (needs the `holdout` extra: fsspec, aiohttp)
"""
import json
import random
import re
from pathlib import Path

CONTROL = re.compile(r'^(C-[a-z]|M-[a-z]|Escape|Enter|Tab|q|y|n|:q!?|:wq)$')


def json_objects(text):
    """Terminus replies are one JSON object, sometimes with text around it."""
    a, b = text.find('{'), text.rfind('}')
    if a < 0 or b <= a:
        return []
    try:
        return [json.loads(text[a:b + 1])]
    except json.JSONDecodeError:
        return []


def keystroke_commands(content):
    out = []
    for obj in json_objects(content):
        for c in obj.get('commands') or []:
            k = c.get('keystrokes') if isinstance(c, dict) else None
            if not isinstance(k, str):
                continue
            k = k.rstrip('\n')
            if k.strip() and not CONTROL.match(k.strip()):
                out.append(k)
    return out


MODELS = ('deepseek', 'gemma', 'gemma_think', 'glm', 'kimi', 'qwen')
BASE = 'https://huggingface.co/datasets/ai-and/termgrade-trajectories/resolve/main/data/messages/'


def termgrade():
    """One row group (~130 trials) per model file, read by HTTP range requests: the rows API rate-limits (429)."""
    import fsspec
    import pyarrow.parquet as pq
    fs, out, got = fsspec.filesystem('https'), [], 0
    rng = random.Random(13)
    for name in MODELS:
        f = pq.ParquetFile(fs.open(BASE + name + '.parquet', block_size=2 ** 20))
        g = rng.randrange(f.metadata.num_row_groups)
        for row in f.read_row_group(g, columns=['task', 'model', 'messages']).to_pylist():
            got += 1
            msgs = row['messages']
            msgs = json.loads(msgs) if isinstance(msgs, str) else msgs
            for m in msgs or []:
                if m.get('role') == 'assistant' and isinstance(m.get('content'), str):
                    for k in keystroke_commands(m['content']):
                        out.append({'text': k, 'source': 'termgrade', 'task': row['task'], 'model': row['model']})
        print(f'termgrade {name}: row group {g}, {got} trials, {len(out)} commands', flush=True)
    return out


def tb2(raw_dir):
    out = []
    p = Path(raw_dir) / 'tb2_all.jsonl'
    if not p.exists():
        return out
    for line in p.open():
        r = json.loads(line)
        for k in keystroke_commands(r.get('response') or ''):
            out.append({'text': k, 'source': 'tb2', 'task': r['task_name'], 'model': f"{r['agent']}/{r['model']}"})
    return out


def fetch(raw_dir, out_path):
    cmds = termgrade() + tb2(raw_dir)
    with open(out_path, 'w') as f:
        for c in cmds:
            f.write(json.dumps(c) + '\n')
    return len(cmds)
