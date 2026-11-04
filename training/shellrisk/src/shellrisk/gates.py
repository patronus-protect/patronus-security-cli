"""Release gates: a candidate K is compared with the released model G on frozen evaluation sets.

Both are scored as bundles (model + the same gated Cedar policies) at their own thresholds. Gate kinds:
  P  absolute product requirements (recall, FPR, latency, fixtures)
  V  absolute targets G misses today (infraset FPR, DefenseClaw held-out)
  R  regression: on every set K may lose at most tol(n) true positives / gain tol(n) false positives vs G,
     and AUC may drop by at most 0.01; if only the TP check fails, K passes when it matches G's TP minus tol
     at both G's and K's false-positive count (matched-FP fallback)
  V  (relative) chance-level sets (G AUC < 0.6): only false positives are gated
  I  invariance: a perturbed set (quoting, padding) may cost K at most what it costs G, against K's own base
  E  equal FPR: at the FPR that G reaches with its two cuts, K's recall may be lower by at most tol(n)
tol(n) = max(1, ceil(0.2 % of the class)).
"""
import json
import math
import time
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from . import corpus as corpus_mod
from . import data
from .model import ASK, BLOCK
from .policies import cedar, core, gate as policy_gate

DC_RULES = Path(cedar.__file__).with_name('dc_rules.json')
MEDIUM = math.log(0.8 / 0.2)  # margin of the "Medium" confidence band (0.8)

# sets derived from earlier robustness work; a perturbed set is measured against its unperturbed base
INVARIANCE = {f'R:{v}': f'R:commands_{shell}' for v, shell in (
    ('paired_bash_quote_command', 'posix'), ('paired_cmd_caret_command', 'cmd'),
    ('tail_padding_posix_4096', 'posix'), ('tail_padding_posix_16384', 'posix'),
    ('tail_padding_powershell_4096', 'powershell'), ('tail_padding_powershell_16384', 'powershell'))}

# Documented exceptions: (candidate, gate) -> reason. A listed gate is still measured and printed, but does
# not fail the candidate. Every entry needs a decision by the model owner, see REPORT.md "Decisions".
EXCEPTIONS = {
    ('k26', 'R:commands_posix'): '2026-11-04: K26 one TP short at matched FP; accepted for -10 agent-holdout FPs',
    ('k26', 'R:tail_padding_posix_4096'): '2026-11-04: +5 FP of 443 under 4 KB padding; accepted, see REPORT.md',
    ('k26', 'R:tail_padding_posix_16384'): '2026-11-04: +4 FP of 443 under 16 KB padding; accepted, see REPORT.md',
}


def tol(n):
    return max(1, math.ceil(0.002 * n))


def evalsets(train_texts):
    """{name: (texts, labels)}; rows of the R: sets that also occur in fit/val are dropped."""
    S = defaultdict(lambda: ([], []))
    for r in data.rows('evalsets.jsonl'):
        if r['set'].startswith('R:') and r['text'] in train_texts:
            continue
        S[r['set']][0].append(r['text']); S[r['set']][1].append(r['label'])
    return dict(S)


def policy_rules(corpus):
    """DefenseClaw rules (fit/val buckets) + core policies, each gated to block / ask / rejected on val."""
    rules = [r for r in json.loads(DC_RULES.read_text())
             if r['status'] == 'translated' and r['bucket'] != 'test'] + core.POLICIES
    gated, _, _ = policy_gate.gate(rules, corpus, cedar.FactsMember)
    return gated


def metrics(score, cuts, texts, y):
    y = np.asarray(y); s = np.asarray(score(texts), dtype=float); e = {'n': len(y), 'npos': int(y.sum())}
    if 0 < y.sum() < len(y):
        e['auc'] = round(roc_auc_score(y, s), 4)
    for p, c in cuts.items():
        pred = s > c
        e[p] = {'recall': round(float(pred[y == 1].mean()), 4) if y.any() else None,
                'fpr': round(float(pred[y == 0].mean()), 4) if (y == 0).any() else None,
                'fp': int(pred[y == 0].sum()), 'tp': int(pred[y == 1].sum())}
    e['margins'] = s - cuts[ASK]
    return e


def _tp_at_fp(margins, y, fp):
    """True positives when the threshold admits exactly fp negatives."""
    neg, pos = y == 0, y == 1
    thr = np.sort(margins[neg])[::-1][fp] if fp < neg.sum() else -np.inf
    return int((margins[pos] > thr).sum())


def latency_pair(score_a, score_b, texts, reps=3000):
    """Interleaved batch-1 latency (p50, p95 in ms), so machine load hits both scorers equally."""
    ta, tb = [], []
    for i in range(reps):
        t = texts[i % len(texts)]
        for sc, acc in ((score_a, ta), (score_b, tb)) if i % 2 == 0 else ((score_b, tb), (score_a, ta)):
            a = time.perf_counter(); sc([t]); acc.append(time.perf_counter() - a)
    q = lambda xs: (round(float(np.percentile(xs, 50)) * 1e3, 3), round(float(np.percentile(xs, 95)) * 1e3, 3))
    return q(ta), q(tb)


def absolute(m, b, y159, lat, lat_g):
    """P and V gates for one bundle b (m = model-only metrics). -> {id: (description, value, value2, ok)}"""
    pos = np.asarray(y159) == 1; marg = b['fixtures_159']['margins']
    ob, cc, sp = b['original_bash'], b['corpus_classic'], b['secret_exfil_probes']['margins']
    dc = b['dc_relabel_heldout']
    return {
        'P1': ('original bash AUC >= 0.995 and recall >= 0.84', ob['auc'], ob[ASK]['recall'],
               ob['auc'] >= 0.995 and ob[ASK]['recall'] >= 0.84),
        'P2': ('classic corpus recall >= 0.92', cc[ASK]['recall'], None, cc[ASK]['recall'] >= 0.92),
        'P3': ('issue #159 fixtures: all positives >= Medium, <= 1 negative flagged',
               int((marg[pos] >= MEDIUM).sum()), int((marg[~pos] > 0).sum()),
               int((marg[pos] >= MEDIUM).sum()) == int(pos.sum()) and int((marg[~pos] > 0).sum()) <= 1),
        'P4': ('benign fixtures: no false positive', b['benign_fixtures'][ASK]['fp'], None,
               b['benign_fixtures'][ASK]['fp'] == 0),
        'P5': ('nl2bash benign FPR <= 0.025', b['nl2bash_benign'][ASK]['fpr'], None,
               b['nl2bash_benign'][ASK]['fpr'] <= 0.025),
        'P6': ('issue #128 AUC >= 0.94 and rogue-security recall at block >= 0.28', b['issue128']['auc'],
               b['rogue_security'][BLOCK]['recall'],
               b['issue128']['auc'] >= 0.94 and b['rogue_security'][BLOCK]['recall'] >= 0.28),
        'P7': ('latency p95 <= 2x G (ms)', lat, lat_g, lat <= 2 * lat_g),
        'P8': ('secret-exfiltration probes all >= Medium', int((sp >= MEDIUM).sum()), len(sp), bool((sp >= MEDIUM).all())),
        'V1': ('infraset benign FPR < 0.05', b['infraset_test'][ASK]['fpr'], None, b['infraset_test'][ASK]['fpr'] < 0.05),
        'V2': ('DefenseClaw held-out AUC >= 0.70 (bundle, model)', dc['auc'], m['dc_relabel_heldout']['auc'],
               dc['auc'] >= 0.70),
        'V3': ('DefenseClaw held-out FPR < 0.25', dc[ASK]['fpr'], None, dc[ASK]['fpr'] < 0.25),
    }


def relative(bg, bk, S):
    """R / V / I gates, K vs G. -> {set: (kind, K summary, G summary, ok)}"""
    out = {}
    for name in bg:
        g, k = bg[name], bk[name]
        npos, nneg = g['npos'], g['n'] - g['npos']
        base = INVARIANCE.get(name)
        if base and base in bg:
            gb, kb = bg[base], bk[base]
            g_lost, k_lost = gb[ASK]['tp'] - g[ASK]['tp'], kb[ASK]['tp'] - k[ASK]['tp']
            g_fp, k_fp = g[ASK]['fp'] - gb[ASK]['fp'], k[ASK]['fp'] - kb[ASK]['fp']
            ok = k_lost <= max(g_lost, 0) + tol(npos) and k_fp <= max(g_fp, 0) + tol(nneg)
            out[name] = ('I', f'TP lost {k_lost:+d} FP {k_fp:+d} vs base', f'{g_lost:+d} {g_fp:+d}', bool(ok))
            continue
        chance = 'auc' in g and g['auc'] < 0.6
        ok, tp_ok, kv, gv = True, True, [], []
        if npos and not chance:
            tp_ok = k[ASK]['tp'] >= g[ASK]['tp'] - tol(npos)
            kv.append(f"TP {k[ASK]['tp']}/{npos}"); gv.append(f"{g[ASK]['tp']}")
        if nneg:
            ok &= k[ASK]['fp'] <= g[ASK]['fp'] + tol(nneg)
            kv.append(f"FP {k[ASK]['fp']}/{nneg}"); gv.append(f"{g[ASK]['fp']}")
        if 'auc' in g and not chance and min(npos, nneg) >= 20:
            ok &= k['auc'] >= g['auc'] - 0.01
            kv.append(f"AUC {k['auc']:.3f}"); gv.append(f"{g['auc']:.3f}")
        if not tp_ok and ok and nneg:
            y = np.asarray(S[name][1])
            pairs = [(f, _tp_at_fp(k['margins'], y, f), _tp_at_fp(g['margins'], y, f))
                     for f in sorted({g[ASK]['fp'], k[ASK]['fp']})]
            tp_ok = all(kt >= gt - tol(npos) for _, kt, gt in pairs)
            kv.append('@FP ' + ','.join(f'{f}:{kt}' for f, kt, _ in pairs))
            gv.append('@FP ' + ','.join(f'{f}:{gt}' for f, _, gt in pairs))
        ok &= tp_ok
        if chance:
            kv.append(f"TP {k[ASK]['tp']}/{npos} AUC {k['auc']:.3f}"); gv.append(f"{g[ASK]['tp']} {g['auc']:.3f}")
        out[name] = ('V' if chance else 'R', ' '.join(kv), ' '.join(gv), bool(ok))
    return out


def equal_fpr(bg, bk, S, names=('original_bash', 'corpus_classic')):
    out = {}
    for name in names:
        y = np.asarray(S[name][1])
        for cut in (ASK, BLOCK):
            fp = bg[name][cut]['fp']
            kt, gt = _tp_at_fp(bk[name]['margins'], y, fp), _tp_at_fp(bg[name]['margins'], y, fp)
            out[f'{name} @FPR {fp}/{int((y == 0).sum())}'] = ('E', f'TP {kt}/{int(y.sum())}', f'{gt}',
                                                            kt >= gt - tol(int(y.sum())))
    return out


def run(name, k_model, g_model, corpus, rules=None):
    """All gates for candidate `name`. -> report dict (JSON-serialisable except margins, which are dropped)."""
    S = evalsets(corpus_mod.training_texts(corpus))
    rules = rules if rules is not None else policy_rules(corpus)
    kept = [r for r in rules if r['level'] != 'rejected']
    member = cedar.FactsMember(kept); levels = {r['id']: r['level'] for r in kept}
    sample = [r['text'] for r in corpus['test'][1][:500]]
    (g50, g95), (k50, k95) = latency_pair(g_model, k_model, sample)
    rep = {'candidate': name, 'cuts': {'G': g_model.thresholds, 'K': k_model.thresholds},
           'latency_ms': {'G': {'p50': g50, 'p95': g95}, 'K': {'p50': k50, 'p95': k95}},
           'policies': {'kept': len(kept), 'levels': {r['id']: [r['level'], r['val_fpr'], r['val_tp']] for r in rules}}}
    B, M = {}, {}
    for who, mdl in (('G', g_model), ('K', k_model)):
        cuts = {ASK: mdl.thresholds[ASK], BLOCK: mdl.thresholds[BLOCK]}
        bund = policy_gate.bundle_scorer(mdl, cuts, member, levels)
        M[who] = {s: metrics(mdl, cuts, *v) for s, v in S.items()}
        B[who] = {s: metrics(bund, cuts, *v) for s, v in S.items()}
    lat = {'G': g95, 'K': k95}
    rep['absolute'] = {w: absolute(M[w], B[w], S['fixtures_159'][1], lat[w], g95) for w in ('G', 'K')}
    rel = relative(B['G'], B['K'], S)
    rel.update(equal_fpr(B['G'], B['K'], S))
    rep['relative'] = {s: list(v) + [EXCEPTIONS.get((name, s))] for s, v in rel.items()}
    rep['sets'] = {w: {s: {k: v for k, v in e.items() if k != 'margins'} for s, e in B[w].items()}
                   for w in B}
    abs_ok = all(v[3] for v in rep['absolute']['K'].values())
    rel_ok = all(v[3] or v[4] for v in rep['relative'].values())
    rep['passed'] = bool(abs_ok and rel_ok)
    return rep


def format_report(rep):
    f = lambda x: '-' if x is None else (f'{x:.3f}' if isinstance(x, float) else str(x))
    lines = [f"Gates for {rep['candidate']}  (K = candidate, G = released model; both as bundles)", '',
             f"{'gate':5} {'requirement':66} {'G':>15}    {'K':>15}"]
    for gid, (desc, *gv) in rep['absolute']['G'].items():
        kv = rep['absolute']['K'][gid]
        lines.append(f"{gid:5} {desc[:66]:66} {f(gv[0]):>7} {f(gv[1]):>7} {'ok' if gv[2] else 'NO':2}  "
                     f"{f(kv[1]):>7} {f(kv[2]):>7} {'ok' if kv[3] else 'FAIL'}")
    lines += ['', f"{'kind':5} {'set':44} {'K':40} {'G':22} result"]
    for s, (kind, kv, gv, ok, exc) in rep['relative'].items():
        res = 'ok' if ok else f'EXCEPTION ({exc})' if exc else 'FAIL'
        lines.append(f'{kind:5} {s:44} {kv:40} {gv:22} {res}')
    n_abs = sum(v[3] for v in rep['absolute']['K'].values())
    n_rel = sum(v[3] for v in rep['relative'].values())
    n_exc = sum(1 for v in rep['relative'].values() if not v[3] and v[4])
    lines += ['', f"absolute {n_abs}/{len(rep['absolute']['K'])}, relative {n_rel}/{len(rep['relative'])}"
                  f"{f' (+{n_exc} documented exceptions)' if n_exc else ''}: {'PASSED' if rep['passed'] else 'FAILED'}"]
    return '\n'.join(lines)
