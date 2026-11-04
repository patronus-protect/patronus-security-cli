"""Agent holdout gate: false positives on real agent commands (TermGrade / Terminal-Bench 2 trajectories).

No prefilter: every extracted command counts, risky ones included. Rows also present in the training corpus
or an evaluation set are dropped, then at most CAP commands per task (seeded) so no task dominates. Each
flagged row gets a label from holdout.labels (rules decided by the model owner); the gate runs on the
task-hash test half: the candidate may not have more labelled false positives than G.
"""
import csv
import math
import random
from collections import defaultdict

import numpy as np

from .. import data
from ..model import ASK, BLOCK
from ..policies import cedar, gate as policy_gate
from . import labels as L

CAP = 25


def wilson(k, n, z=1.96):
    if not n:
        return (0.0, 0.0)
    p = k / n; d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d; h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def holdout_rows(corpus):
    seen = {data.fingerprint(r['text']) for s in corpus for r in corpus[s][1]}
    seen |= {data.fingerprint(r['text']) for r in data.rows('evalsets.jsonl')
             if r['set'] in ('infraset_test', 'dc_relabel_heldout')}
    raw = data.rows('agent_holdout.jsonl')
    uniq, fps = [], set()
    for r in raw:
        fp = data.fingerprint(r['text'])
        if fp not in fps and fp not in seen:
            fps.add(fp); uniq.append(r)
    by_task = defaultdict(list)
    for r in uniq:
        by_task[(r['source'], r['task'])].append(r)
    rng = random.Random(13)
    out = []
    for k in sorted(by_task):
        rs = by_task[k]
        out += rs if len(rs) <= CAP else rng.sample(rs, CAP)
    return out, {'raw': len(raw), 'unique_unseen': len(uniq), 'tasks': len(by_task), 'capped': len(out)}


def _decision(s, cuts):
    return 'block' if s > cuts[BLOCK] else 'ask' if s > cuts[ASK] else 'allow'


def run(models, rules, corpus):
    """models: {'G': LinearModel, '<candidate>': LinearModel, ...}; rules: gated policies of the candidate."""
    rows, counts = holdout_rows(corpus)
    texts = [r['text'] for r in rows]
    kept = [r for r in rules if r['level'] != 'rejected']
    member = cedar.FactsMember(kept); levels = {r['id']: r['level'] for r in kept}
    S = {}
    for who, m in models.items():
        cuts = {ASK: m.thresholds[ASK], BLOCK: m.thresholds[BLOCK]}
        S[who] = {'bundle': np.asarray(policy_gate.bundle_scorer(m, cuts, member, levels)(texts)), 'cuts': cuts}
    lab = [L.prelabel(t) for t in texts]
    half = [L.split(r['task']) for r in rows]
    rep = {'counts': counts, 'models': {}, 'gate': {}}
    for who, v in S.items():
        flag = v['bundle'] > v['cuts'][ASK]
        e = {'flags': int(flag.sum()), 'block': int((v['bundle'] > v['cuts'][BLOCK]).sum()), 'n': len(texts),
             'ci': wilson(int(flag.sum()), len(texts)),
             'tasks_flagged': len({rows[i]['task'] for i in np.flatnonzero(flag)})}
        for part in ('dev', 'test'):
            ix = [i for i in np.flatnonzero(flag) if half[i] == part]
            e[part] = {'flags': len(ix), 'false_pos': sum(lab[i][0] == 0 for i in ix),
                       'justified': sum(lab[i][0] == 1 for i in ix), 'open': sum(lab[i][0] is None for i in ix)}
        rep['models'][who] = e
    g = rep['models']['G']['test']
    for who in models:
        if who != 'G':
            k = rep['models'][who]['test']
            # open rows count as false positives for both: a missing label never favours the candidate
            rep['gate'][who] = {'candidate': k['false_pos'] + k['open'], 'G': g['false_pos'] + g['open']}
            rep['gate'][who]['ok'] = rep['gate'][who]['candidate'] <= rep['gate'][who]['G']
    flagged = sorted({int(i) for v in S.values() for i in np.flatnonzero(v['bundle'] > v['cuts'][ASK])},
                     key=lambda i: (lab[i][0] is not None, half[i], i))
    rep['review'] = [{'idx': i, 'label': lab[i][0], 'basis': lab[i][1], 'half': half[i], 'task': rows[i]['task'],
                      **{f'{w}_decision': _decision(S[w]['bundle'][i], S[w]['cuts']) for w in S},
                      'text': texts[i][:600]} for i in flagged]
    return rep


def write_review(rep, path):
    with open(path, 'w', newline='') as f:
        wr = csv.DictWriter(f, fieldnames=list(rep['review'][0]) if rep['review'] else ['idx'])
        wr.writeheader(); wr.writerows(rep['review'])


def format_report(rep):
    c = rep['counts']
    lines = [f"Agent holdout: {c['capped']} commands from {c['tasks']} tasks "
             f"({c['raw']} raw, {c['unique_unseen']} unique and unseen)", '',
             f"{'model':10} {'flags':>6} {'rate':>7} {'95% CI':>15} {'block':>6} {'tasks':>6}   "
             f"{'test: FP / justified':>21}   {'dev: FP / justified':>20}"]
    for who, e in rep['models'].items():
        lines.append(f"{who:10} {e['flags']:6} {e['flags'] / e['n']:7.2%} {e['ci'][0]:6.2%}-{e['ci'][1]:6.2%} "
                     f"{e['block']:6} {e['tasks_flagged']:6}   {e['test']['false_pos']:>12} / {e['test']['justified']:<6}"
                     f"   {e['dev']['false_pos']:>11} / {e['dev']['justified']:<6}")
    lines.append('')
    for who, gt in rep['gate'].items():
        lines.append(f"gate {who}: test false positives {gt['candidate']} <= G {gt['G']}: {'PASSED' if gt['ok'] else 'FAILED'}")
    return '\n'.join(lines)
