"""Training corpus for one run: frozen base corpus + infraset benign commands + DefenseClaw relabels + templates.

Every row has text, label (1 = risky), family, group_id, split (fit | val | test) and a sample weight w.
Rows are de-duplicated by fingerprint in a fixed order (base corpus first), so a later source never
overrides an earlier label. Synthetic template rows go to fit/val only (85/15 by text hash).
"""
import hashlib

import numpy as np

from . import data, templates

DEFAULTS = {'infra_n': 1000, 'infra_w': 1.0, 'dc': True, 'dc_w': 1.0, 'aug': False, 'contrast': False,
            'agent_aug': False, 'aug_skip': [], 'aug_w': 1.0, 'aug_group_w': {}, 'seed': 13}

# Families added after the classic corpus. They are excluded when the thresholds are calibrated, so the
# 1 % / 0.1 % cuts stay comparable with the reference model G.
NEW_FAMILIES = ('issue159', 'aug159', 'aug_heredoc', 'aug_ops', 'ops_', 'heredoc_', 'agent_code',
                'agent_shell', 'aug_publish', 'publish_', 'dc_', 'infraset', 'dc_relabel', 'aug_k')


def base():
    rows = data.rows('corpus.jsonl')
    return {s: [r for r in rows if r['split'] == s] for s in ('fit', 'val', 'test')}


def load(cfg):
    """{split: (labels array, rows)} for the run configuration cfg (see DEFAULTS)."""
    cfg = dict(DEFAULTS, **cfg)
    rows = base()
    seen = {data.fingerprint(r['text']) for s in rows for r in rows[s]}
    add = []

    infra = data.rows('infraset_pool.jsonl')
    fit_inf = [r for r in infra if r['split'] == 'fit']
    rng = np.random.default_rng(cfg['seed'])
    n = min(cfg['infra_n'], len(fit_inf))
    pick = set(rng.choice(len(fit_inf), size=n, replace=False).tolist()) if n else set()
    add += [dict(r, w=cfg['infra_w']) for i, r in enumerate(fit_inf) if i in pick]
    add += [dict(r, w=cfg['infra_w']) for r in infra if r['split'] == 'val']

    if cfg['dc']:
        for r in data.repo_rows('dc_relabelled.jsonl'):
            if r['bucket'] != 'test':  # the test bucket is the dc_relabel_heldout evaluation set
                add.append({'text': r['text'], 'label': r['label'], 'family': 'dc_relabel',
                            'group_id': 'dc/' + r['rule_id'], 'split': r['bucket'], 'w': cfg['dc_w']})

    if cfg['aug']:
        skip = tuple('augk/' + g for g in cfg['aug_skip'])
        synth = templates.rows() + (templates.contrast_rows() if cfg['contrast'] else []) + \
            (templates.agent_test_rows() if cfg['agent_aug'] else [])
        for r in synth:
            if skip and r['group_id'].startswith(skip):
                continue
            h = int(hashlib.sha256(('augk:' + r['text']).encode()).hexdigest(), 16) % 100
            gw = cfg['aug_group_w'].get(r['group_id'].split('/', 1)[1], 1.0)
            add.append(dict(r, split='fit' if h < 85 else 'val', w=cfg['aug_w'] * gw))

    for r in add:
        fp = data.fingerprint(r['text'])
        if fp not in seen:
            seen.add(fp)
            rows[r['split']].append(r)
    return {s: (np.array([r['label'] for r in rows[s]]), rows[s]) for s in rows}


def training_texts(corpus):
    """Texts of fit and val: evaluation rows identical to one of them are dropped from the R: sets."""
    return {r['text'] for s in ('fit', 'val') for r in corpus[s][1]}
