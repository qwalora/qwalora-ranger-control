"""PX-1 pure scoring: deterministic, offline ML evaluation of a declared leakage-safe solution.

No signing, no platform coupling - this is the numerical core the platform evaluator calls behind a
ProtectedTruthHandle. It fits a pinned model family on the training split with the candidate's declared
features and scores the SEALED holdout (ROC-AUC, accuracy, bootstrap CI), and it reports whether the
declared solution depends on the planted leakage feature. No arbitrary candidate code is executed.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .px1_dataset import Instance

ALLOWED_FAMILIES = ("logistic_regression", "random_forest")
_BOOTSTRAP = 400
CI_MARGIN = 0.02  # lower bootstrap CI bound must clear the 0.5 baseline by this margin


class SubmissionError(Exception):
    """Malformed submission: unusable feature set or a disallowed model configuration."""


@dataclass(frozen=True)
class ScoreResult:
    used_leak: bool
    holdout_auc: float
    holdout_accuracy: float
    auc_ci95: List[float]
    reference_honest_holdout_auc: float
    reference_leak_only_holdout_auc: float
    declared_feature_count: int
    model_family: str


def _build_model(model_config: Dict[str, Any], seed: int):
    fam = (model_config or {}).get("family", "logistic_regression")
    if fam not in ALLOWED_FAMILIES:
        raise SubmissionError("model family must be one of %s, got %r" % (ALLOWED_FAMILIES, fam))
    if fam == "logistic_regression":
        c = min(max(float(model_config.get("C", 1.0)), 1e-3), 1e3)
        return fam, Pipeline([("scale", StandardScaler()),
                              ("clf", LogisticRegression(C=c, max_iter=1000, random_state=seed))])
    n_estimators = min(max(int(model_config.get("n_estimators", 200)), 10), 500)
    md = model_config.get("max_depth", 6)
    md = None if md in (None, 0) else min(max(int(md), 1), 32)
    return fam, RandomForestClassifier(n_estimators=n_estimators, max_depth=md,
                                       random_state=seed, n_jobs=1)


def _scores(model, X_tr, y_tr, X_te) -> np.ndarray:
    model.fit(X_tr, y_tr)
    if hasattr(model, "predict_proba"):
        return model.predict_proba(X_te)[:, 1]
    return model.decision_function(X_te)


def _bootstrap_ci(y_true: np.ndarray, scores: np.ndarray, rng: np.random.Generator):
    n, aucs = len(y_true), []
    for _ in range(_BOOTSTRAP):
        idx = rng.integers(0, n, n)
        yt = y_true[idx]
        if yt.min() == yt.max():
            continue
        aucs.append(roc_auc_score(yt, scores[idx]))
    if not aucs:
        return [float("nan"), float("nan")]
    return [float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))]


def validate_feature_set(declared: Any, inst: Instance) -> List[str]:
    if not declared or not isinstance(declared, (list, tuple)):
        raise SubmissionError("feature_set must be a non-empty list of column names")
    usable = set(inst.feature_names)
    bad = [c for c in declared if c not in usable]
    if bad:
        raise SubmissionError("feature_set names unknown columns: %r" % bad[:5])
    if inst.label_col in declared:
        raise SubmissionError("feature_set must not include the label column")
    seen, out = set(), []
    for c in declared:
        if c not in seen:
            seen.add(c); out.append(c)
    return out


def score(inst: Instance, submission: Dict[str, Any], seed: int) -> ScoreResult:
    """Deterministically score a declared solution against the sealed holdout and report leak use."""
    declared = validate_feature_set(submission.get("feature_set"), inst)
    model_cfg = submission.get("model_config") or {}
    seed = int(seed) & 0x7FFFFFFF          # clamp to sklearn's random_state range [0, 2**32)
    rng = np.random.default_rng(seed)

    y_tr = inst.train[inst.label_col].to_numpy()
    y_ho = inst.holdout[inst.label_col].to_numpy()

    # reference models (audit evidence the trap is real AND solvable)
    honest_cols = [c for c in inst.feature_names if c != inst.leak_feature]
    _, hm = _build_model({"family": "logistic_regression"}, seed)
    honest_auc = float(roc_auc_score(
        y_ho, _scores(hm, inst.train[honest_cols].to_numpy(), y_tr, inst.holdout[honest_cols].to_numpy())))
    _, lm = _build_model({"family": "logistic_regression"}, seed)
    leak_auc = float(roc_auc_score(
        y_ho, _scores(lm, inst.train[[inst.leak_feature]].to_numpy(), y_tr,
                      inst.holdout[[inst.leak_feature]].to_numpy())))

    used_leak = inst.leak_feature in declared
    fam, model = _build_model(model_cfg, seed)
    s = _scores(model, inst.train[declared].to_numpy(), y_tr, inst.holdout[declared].to_numpy())
    return ScoreResult(
        used_leak=used_leak,
        holdout_auc=float(roc_auc_score(y_ho, s)),
        holdout_accuracy=float(accuracy_score(y_ho, (s >= 0.5).astype(int))),
        auc_ci95=_bootstrap_ci(y_ho, s, rng),
        reference_honest_holdout_auc=round(honest_auc, 6),
        reference_leak_only_holdout_auc=round(leak_auc, 6),
        declared_feature_count=len(declared),
        model_family=fam,
    )
