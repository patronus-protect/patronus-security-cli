"""Fit one candidate: two TF-IDF blocks (char_wb 3-5 n-grams, kf1 tokens) + logistic regression.

C is picked by the mean average precision over the validation families. The two thresholds are calibrated
on the classic validation mixture (NEW_FAMILIES excluded): 1 % FPR = ask, 0.1 % FPR = block.
"""
import time
from collections import defaultdict

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from . import features
from .corpus import NEW_FAMILIES
from .model import ASK, BLOCK, LinearModel


def vectorizers(analyzer):
    return [TfidfVectorizer(analyzer='char_wb', ngram_range=(3, 5), max_features=50000, min_df=2,
                            sublinear_tf=True, dtype=np.float32),
            TfidfVectorizer(analyzer=analyzer, max_features=40000, min_df=2, sublinear_tf=True, dtype=np.float32)]


def fpr_cut(scores, y, fpr):
    """Score above which a fraction fpr of the negatives lies."""
    neg = np.sort(scores[y == 0])[::-1]
    return float(neg[min(int(np.floor(fpr * len(neg))), len(neg) - 1)]) if len(neg) else 0.0


def calibrate(score, corpus):
    yv, vr = corpus['val']
    keep = np.array([i for i, r in enumerate(vr) if not r['family'].startswith(NEW_FAMILIES)])
    s = score([vr[i]['text'] for i in keep])
    return {ASK: fpr_cut(s, yv[keep], 0.01), BLOCK: fpr_cut(s, yv[keep], 0.001)}


def fit(cfg, corpus):
    """-> (LinearModel with calibrated thresholds, info dict)."""
    analyzer = getattr(features, cfg.get('features', 'kf1'))
    (yf, fr), (yv, vr) = corpus['fit'], corpus['val']
    vecs = vectorizers(analyzer)
    t0 = time.perf_counter()
    xf = sp.hstack([v.fit_transform([r['text'] for r in fr]) for v in vecs]).tocsr()
    xv = sp.hstack([v.transform([r['text'] for r in vr]) for v in vecs]).tocsr()
    w = np.array([r.get('w', 1.0) * (cfg.get('pos_w', 1.0) if y == 1 else 1.0) for r, y in zip(fr, yf)])
    fams = defaultdict(list)
    for i, r in enumerate(vr):
        fams[r['family']].append(i)
    best, hist = None, []
    for C in cfg.get('C', [10]):
        m = LogisticRegression(C=C, max_iter=3000, random_state=13).fit(xf, yf, sample_weight=w)
        s = m.decision_function(xv)
        ap = float(np.mean([average_precision_score(yv[i], s[i]) for i in fams.values() if 0 < yv[i].sum() < len(i)]))
        hist.append({'C': C, 'macro_val_ap': round(ap, 4)})
        if best is None or ap > best[0]:
            best = (ap, C, m)
    _, C, m = best
    model = LinearModel(vecs, m.coef_.ravel(), m.intercept_[0], {})
    model.thresholds = calibrate(model, corpus)
    return model, {'C': C, 'history': hist, 'features': int(xf.shape[1]), 'fit_rows': len(yf),
                   'fit_seconds': round(time.perf_counter() - t0, 1)}
