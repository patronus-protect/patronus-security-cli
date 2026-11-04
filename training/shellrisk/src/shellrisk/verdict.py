"""patronus.verdict/1: one decision per command from model + Cedar policies over patronus.facts/1.

    bundle = Bundle.load('models/k26')            # model.json + gated policy levels from gates.json
    v = bundle.score(command, context=None, prior_facts=None)

Result (canonical JSON via schema.dumps):
  {
    "v": "patronus.verdict/1",
    "decision": "allow" | "ask" | "block",
    "score": <bundle score, model logit raised to the policy floor>,
    "cuts": {"ask": <1 % FPR cut>, "block": <0.1 % FPR cut>},
    "model": {"id", "score", "decision", "top_features": [{"feature", "weight"}]},
    "policies": [{"id", "tier", "title", "decision", "where"}],   # fired policies, strongest first
    "allowlisted": [{"id", "from", "to"}],                       # bundle-default hits lowered by the caller
    "facts": <patronus.facts/1>
  }

Decision = max(model, policies) on allow < ask < block, the same rule the gates measure (policies/gate.bundle_scorer):
the model asks above the 1 % cut and blocks above the 0.1 % cut; a fired policy sets at least its level.

Policy tiers:
  core            Patronus core policies (policies/core.py). Never lowered.
  bundle-default  translated DefenseClaw rules (policies/dc_rules.json). The caller may lower one block to ask via
                  `allowlist` (id -> "ask"); nothing goes to allow, and core ids are refused.
  user            caller policies: forbid only, decision block|ask, no regex, ids `user.*`, each one checked
                  against the Cedar schema and required to parse as exactly one policy.
Policies the val gate rejected are not loaded. Context and prior facts are trusted (security harness) and reach
the policies through the facts; the model sees the command text only (it was trained without context).
"""
import json
import re
from pathlib import Path

import cedarpy
import numpy as np

from . import data
from .facts.extract import extract
from .model import ASK, BLOCK, LinearModel
from .policies import cedar as cedar_facts
from .policies import core as core_policies

VERSION = 'patronus.verdict/1'
RANK = {'allow': 0, 'ask': 1, 'block': 2}
USER_ID = re.compile(r'^user\.[A-Za-z0-9_.-]{1,64}$')


def _decide(score, cuts):
    return 'block' if score > cuts['block'] else 'ask' if score > cuts['ask'] else 'allow'


def check_user_policies(policies):
    """Strict validation of caller policies; returns them in the internal rule shape or raises ValueError."""
    out, seen = [], set()
    for p in policies:
        extra = set(p) - {'id', 'decision', 'scope', 'condition', 'title'}
        if extra:
            raise ValueError(f'user policy {p.get("id")}: unknown fields {sorted(extra)}')
        pid = p.get('id', '')
        if not USER_ID.match(pid) or pid in seen:
            raise ValueError(f'user policy id must be unique and match user.*: {pid!r}')
        if p.get('decision') not in ('block', 'ask'):
            raise ValueError(f'{pid}: decision must be block or ask')
        if p.get('scope', 'segment') not in ('segment', 'command'):
            raise ValueError(f'{pid}: scope must be segment or command')
        r = {'id': pid, 'tier': 'user', 'cap': p['decision'], 'level': p['decision'], 'scope': p.get('scope', 'segment'),
             'title': p.get('title', pid), 'condition': p['condition'], 'pattern': None}
        text = cedar_facts.policy_text([r])
        try:
            n = len(json.loads(cedarpy.policies_to_json_str(text))['staticPolicies'])
        except Exception as e:  # noqa: BLE001 - any parse failure is a refusal
            raise ValueError(f'{pid}: does not parse: {e}') from None
        if n != 2:  # base permit + this forbid; anything else means the condition escaped its clause
            raise ValueError(f'{pid}: condition must form exactly one policy')
        ok, errs = cedar_facts.validate([r])
        if not ok:
            raise ValueError(f'{pid}: schema validation failed: {errs[:2]}')
        seen.add(pid); out.append(r)
    return out


class Bundle:
    def __init__(self, model, rules, model_id):
        self.model, self.model_id = model, model_id
        self.cuts = {'ask': float(model.thresholds[ASK]), 'block': float(model.thresholds[BLOCK])}
        self.rules = rules
        self.names = None
        self._sets = {}  # parsed PolicySet per user-policy set; parsing dominates a Cedar call otherwise

    @classmethod
    def load(cls, model_dir=None):
        """model_dir holds model.json and gates.json (policy levels from the val gate); default models/k26."""
        model_dir = Path(model_dir or data.MODELS / 'k26')
        gate = json.loads((model_dir / 'gates.json').read_text())['policies']['levels']
        dc = [r for r in json.loads(Path(cedar_facts.__file__).with_name('dc_rules.json').read_text())
              if r['status'] == 'translated' and r['bucket'] != 'test']
        rules = []
        for r in dc + core_policies.POLICIES:
            level = gate.get(r['id'], ['rejected'])[0]
            if level != 'rejected':
                rules.append({**r, 'tier': r.get('tier') or 'bundle-default', 'level': level})
        return cls(LinearModel.load(model_dir / 'model.json'), rules, model_dir.name)

    # ------------------------------------------------------------------ model
    def _model(self, command, k=5):
        s = float(self.model([command])[0])
        if self.names is None:
            self.names = self.model.feature_names()
        import scipy.sparse as sp
        row = sp.hstack([v.transform([command]) for v in self.model.vectorizers]).tocsr().getrow(0)
        contrib = row.data * self.model.weights[row.indices]
        top = [{'feature': self.names[row.indices[i]], 'weight': round(float(contrib[i]), 4)}
               for i in np.argsort(-contrib)[:k] if contrib[i] > 0]
        return s, top

    # ------------------------------------------------------------------ policies
    def _policies(self, facts, command, user, allowlist):
        rules = self.rules + user
        pats = {f'p{i}' for i, r in enumerate(rules) if r.get('pattern') and re.search(r['pattern'], command)}
        reqs = cedar_facts.requests(facts, pats)
        where = [f"segment:{s['id']}" for s in facts['segments']] + ['command']
        fired = {}
        key = tuple((r['id'], r['scope'], r['condition']) for r in user)
        if key not in self._sets:
            self._sets[key] = cedarpy.PolicySet.from_str(cedar_facts.policy_text(rules))
        for w, res in zip(where, cedarpy.is_authorized_batch(reqs, self._sets[key], [])):
            if res.diagnostics.errors:
                raise RuntimeError(res.diagnostics.errors[:2])
            for pid in res.diagnostics.reasons:
                k = int(pid.replace('policy', ''))
                if k > 0:
                    fired.setdefault(k - 1, []).append(w)
        hits, lowered = [], []
        for i, ws in fired.items():
            r = rules[i]; dec = r['level']
            if r['tier'] == 'bundle-default' and allowlist.get(r['id']) == 'ask' and dec == 'block':
                lowered.append({'id': r['id'], 'from': 'block', 'to': 'ask'}); dec = 'ask'
            hits.append({'id': r['id'], 'tier': r['tier'], 'title': r.get('title') or r['id'], 'decision': dec,
                         'where': sorted(set(ws))})
        hits.sort(key=lambda h: (-RANK[h['decision']], h['tier'] != 'core', h['id']))
        return hits, sorted(lowered, key=lambda x: x['id'])

    def check_allowlist(self, allowlist):
        tiers = {r['id']: r['tier'] for r in self.rules}
        for pid, to in allowlist.items():
            if to != 'ask':
                raise ValueError(f'allowlist {pid}: a policy can only be lowered to ask')
            if tiers.get(pid) != 'bundle-default':
                raise ValueError(f'allowlist {pid}: only loaded bundle-default policies can be lowered '
                                 f'(tier: {tiers.get(pid, "unknown")})')
        return dict(allowlist)

    # ------------------------------------------------------------------ verdict
    def score(self, command, context=None, prior_facts=None, user_policies=(), allowlist=None):
        user = check_user_policies(user_policies) if user_policies else []
        allow = self.check_allowlist(allowlist or {})
        facts = extract(command, context=context, prior_facts=prior_facts)
        ms, top = self._model(command)
        hits, lowered = self._policies(facts, command, user, allow)
        floor = max((RANK[h['decision']] for h in hits), default=0)
        # policy floors as in bundle_scorer: ask sits between the two cuts, block clearly above the block cut
        s = ms
        if floor == 2:
            s = max(s, self.cuts['block'] + 2.0)
        elif floor == 1:
            s = max(s, (self.cuts['ask'] + self.cuts['block']) / 2)
        decision = _decide(s, self.cuts)
        return {'v': VERSION, 'decision': decision, 'score': round(s, 4),
                'cuts': {k: round(v, 6) for k, v in self.cuts.items()},
                'model': {'id': self.model_id, 'score': round(ms, 4), 'decision': _decide(ms, self.cuts),
                          'top_features': top},
                'policies': hits, 'allowlisted': lowered, 'facts': facts}
