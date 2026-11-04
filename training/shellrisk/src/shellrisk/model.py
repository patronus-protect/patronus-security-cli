"""Linear TF-IDF model in the released JSON format (format_version 2), no pickle.

A model is a list of TF-IDF blocks (char_wb n-grams, and a token block with a named analyzer function),
one weight vector over their concatenation, an intercept and named thresholds on the decision score.
The reference model G and every candidate use this format, so the Rust runtime can load either.
"""
import importlib.util
import json
import sys
from pathlib import Path

import numpy as np
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer

ASK, BLOCK = 'external_commands_1pct_fpr', 'block_0_1pct_fpr'
FORMAT = 2


class LinearModel:
    def __init__(self, vectorizers, weights, intercept, thresholds, meta=None):
        self.vectorizers = vectorizers
        self.weights = np.asarray(weights, dtype=np.float64)
        self.intercept = float(intercept)
        self.thresholds = dict(thresholds)
        self.meta = meta or {}

    def decision_function(self, texts):
        if isinstance(texts, str):
            raise TypeError('pass a list of strings')
        x = sp.hstack([v.transform(texts) for v in self.vectorizers]).tocsr()
        return np.asarray(x @ self.weights).reshape(-1) + self.intercept

    __call__ = decision_function

    def feature_names(self):
        return [f'{"char" if v.analyzer == "char_wb" else "tok"}:{n}'
                for v in self.vectorizers for n in v.get_feature_names_out()]

    def save(self, path, analyzer_module='shellrisk.features'):
        blocks = []
        for v in self.vectorizers:
            b = {'feature_dtype': np.dtype(v.dtype).name, 'idf_dtype': v.idf_.dtype.name,
                 'vocabulary': {k: int(i) for k, i in v.vocabulary_.items()}, 'idf': v.idf_.tolist()}
            if v.analyzer == 'char_wb':
                b.update(kind='char_wb', vectorizer={'analyzer': 'char_wb', 'ngram_range': list(v.ngram_range),
                                                     'lowercase': v.lowercase, 'sublinear_tf': v.sublinear_tf,
                                                     'min_df': v.min_df})
            else:
                b.update(kind='tokens', analyzer_module=analyzer_module, analyzer_func=v.analyzer.__name__,
                         vectorizer={'sublinear_tf': v.sublinear_tf, 'min_df': v.min_df})
            blocks.append(b)
        out = {'format_version': FORMAT, 'decision_rule': 'score > threshold', 'blocks': blocks,
               'weights': self.weights.tolist(), 'intercept': self.intercept, 'thresholds': self.thresholds,
               'default_threshold_policy': ASK, **self.meta}
        Path(path).write_text(json.dumps(out))

    @classmethod
    def load(cls, path, analyzer_module=None):
        """analyzer_module: module object holding the token analyzer; default: the one the file names."""
        d = json.loads(Path(path).read_text())
        if d['format_version'] != FORMAT:
            raise ValueError(f'{path}: unsupported format_version {d["format_version"]}')
        vecs = []
        for b in d['blocks']:
            cfg = dict(b['vectorizer'], dtype=np.dtype(b['feature_dtype']).type)
            if b['kind'] == 'char_wb':
                cfg['ngram_range'] = tuple(cfg['ngram_range'])
            else:
                mod = analyzer_module or importlib.import_module(b['analyzer_module'])
                cfg['analyzer'] = getattr(mod, b['analyzer_func'])
            v = TfidfVectorizer(vocabulary=b['vocabulary'], **cfg)
            v.idf_ = np.asarray(b['idf'], dtype=b['idf_dtype'])
            vecs.append(v)
        meta = {k: v for k, v in d.items() if k not in ('format_version', 'decision_rule', 'blocks', 'weights',
                                                        'intercept', 'thresholds', 'default_threshold_policy')}
        return cls(vecs, d['weights'], d['intercept'], d['thresholds'], meta)


def load_reference_g(release_dir):
    """The released model G. Its token analyzer is the tokenizer frozen with that release (shell_tokens.py in
    the release directory, an earlier version of shellrisk.tokens), loaded under its own module name."""
    release_dir = Path(release_dir)
    spec = importlib.util.spec_from_file_location('shellrisk_reference_g_tokens', release_dir / 'shell_tokens.py')
    tok = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = tok
    keep, sys.dont_write_bytecode = sys.dont_write_bytecode, True  # never write into the data directory
    try:
        spec.loader.exec_module(tok)
    finally:
        sys.dont_write_bytecode = keep
    return LinearModel.load(release_dir / 'model.json', analyzer_module=tok)
