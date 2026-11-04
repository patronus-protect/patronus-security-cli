"""Policy gate and bundle scorer.

gate(): each policy gets a level from its false-positive rate on the validation negatives (never on an
evaluation set): a `block`-capped policy with FPR <= 0.1 % blocks, FPR <= 1 % asks, otherwise it is rejected.
A union budget then rejects the weakest policies once their combined benign hits exceed 0.2 % of the negatives.

bundle_scorer(): score = max(model score, policy floor); the floor is block cut + 2 for a `block` policy and
the midpoint of the two cuts for an `ask` policy.
"""
from collections import Counter

import numpy as np


def gate(rules, data, member_cls):
    member = member_cls(rules)
    yv, vr = data['val']
    neg = [r['text'] for r, y in zip(vr, yv) if y == 0]
    pos = [r['text'] for r, y in zip(vr, yv) if y == 1]
    fp, tp = Counter(), Counter()
    for h in member.hits(neg):
        fp.update(h)
    for h in member.hits(pos):
        tp.update(h)
    out = []
    for r in rules:
        rate = fp[r['id']] / len(neg)
        level = 'block' if r['cap'] == 'block' and rate <= 0.001 else 'ask' if rate <= 0.01 else 'rejected'
        out.append({**r, 'level': level, 'val_fpr': round(rate, 5), 'val_fp': fp[r['id']], 'val_tp': tp[r['id']]})
    # Union budget: per-rule FPs add up. Keep rules by val TP/FP (best first) until the union of their
    # benign hits would exceed BUDGET of all val negatives; the rest is rejected.
    BUDGET = 0.002
    neg_hits = dict(zip(neg, member.hits(neg)))
    covered, order = set(), sorted([r for r in out if r['level'] != 'rejected'],
                                   key=lambda r: (r['val_fp'] - 3 * r['val_tp'], r['id']))
    for r in order:
        new = {t for t, h in neg_hits.items() if r['id'] in h} - covered
        if (len(covered) + len(new)) / len(neg) > BUDGET:
            r['level'] = 'rejected'; r['reason'] = 'union FP budget'
        else:
            covered |= new
    return out, len(neg), len(pos)


def bundle_scorer(g_score, cuts, member, levels):
    s_block = cuts['block_0_1pct_fpr'] + 2.0
    s_ask = (cuts['external_commands_1pct_fpr'] + cuts['block_0_1pct_fpr']) / 2
    def score(texts):
        s = np.asarray(g_score(texts), dtype=float).copy()
        for i, h in enumerate(member.hits(texts)):
            lv = {levels[x] for x in h}
            if 'block' in lv:
                s[i] = max(s[i], s_block)
            elif 'ask' in lv:
                s[i] = max(s[i], s_ask)
        return s
    return score
