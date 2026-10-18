"""PX-1 instance dataset: deterministic generation from a verified GenerationContract.

Produces a binary-classification instance with three splits:
  - train            disclosed to the candidate (features + label)
  - validation       disclosed to the candidate (features + label), the "public" split
  - holdout          SEALED: generated here for the grader only; labels never disclosed

The instance contains honest, generalizing signal features and exactly one planted LEAKAGE feature.
The leak is a target leak: on train/validation it is near-perfectly predictive of the label, but on
the holdout it is independent of the label. A model that relies on the leak scores high on validation
and collapses to baseline on the holdout; a leakage-safe model that uses the honest features
generalizes to the holdout. The leak column's identity is sealed in the contract params, never in the
candidate brief.

Everything is derived from `contract.seed()`, so the grader reproduces the identical instance from the
signed contract alone (independent verification), and each (candidate, attempt) gets a distinct
instance (non-transfer).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd

from .contracts import GenerationContract

# Instance shape (kept small so evaluation is fast and fully offline).
N_HONEST = 6          # honest, generalizing signal features
N_NOISE = 5           # pure-noise features
N_TRAIN = 1200
N_VALID = 600
N_HOLDOUT = 600


@dataclass(frozen=True)
class Instance:
    train: pd.DataFrame
    validation: pd.DataFrame
    holdout: pd.DataFrame            # SEALED (includes the label, for the grader only)
    feature_names: List[str]         # all usable feature column names (leak identity NOT marked)
    leak_feature: str                # SEALED: the planted leakage column name
    label_col: str = "label"

    def public_feature_names(self) -> List[str]:
        """Column names the candidate legitimately sees - every feature, with the leak unmarked."""
        return list(self.feature_names)


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-z))


def _gen_split(rng: np.random.Generator, n: int, w: np.ndarray, n_honest: int, n_noise: int,
               leak_idx: int, leak_informative: bool) -> Tuple[np.ndarray, np.ndarray]:
    """Generate one split's feature matrix X and label y.

    Honest features drive the label through a fixed linear logit `w` (the same signal in every split,
    so it generalizes). The leak column is a near-copy of the label when `leak_informative` (train/
    validation) and independent noise otherwise (holdout)."""
    n_feat = n_honest + n_noise + 1  # +1 leak column
    X = rng.standard_normal((n, n_feat))
    honest = X[:, :n_honest]
    logit = honest @ w
    p = _sigmoid(logit)
    y = (rng.random(n) < p).astype(int)
    if leak_informative:
        # near-perfect predictor: label with ~3% random flips
        flips = rng.random(n) < 0.03
        leak_val = np.where(flips, 1 - y, y).astype(float)
        # add small continuous jitter so it is not a literal duplicate of the label column
        leak_val = leak_val + rng.normal(0, 0.05, n)
    else:
        # holdout: the leak is independent of the label (the leakage does not generalize)
        leak_val = rng.normal(0, 1.0, n)
    X[:, leak_idx] = leak_val
    return X, y


def generate(contract: GenerationContract) -> Instance:
    """Deterministically build the PX-1 instance for a verified contract. The caller is expected to
    have already `resolve()`d the contract against its spec."""
    seed = contract.seed()
    rng = np.random.default_rng(seed)

    n_honest, n_noise = N_HONEST, N_NOISE
    n_feat = n_honest + n_noise + 1
    # fixed honest signal weights for this instance (generalizes across splits)
    w = rng.normal(0, 1.4, n_honest)

    # place the leak column at a per-instance position so its index is not constant across candidates
    leak_idx = int(rng.integers(0, n_feat))

    # neutral, uniform column names so the leak is not identifiable by name - only by analysis
    feature_names = [f"x{i:02d}" for i in range(n_feat)]
    leak_feature = feature_names[leak_idx]

    def _frame(n: int, leak_informative: bool) -> pd.DataFrame:
        X, y = _gen_split(rng, n, w, n_honest, n_noise, leak_idx, leak_informative)
        df = pd.DataFrame(X, columns=feature_names)
        df["label"] = y
        return df

    train = _frame(N_TRAIN, leak_informative=True)
    validation = _frame(N_VALID, leak_informative=True)
    holdout = _frame(N_HOLDOUT, leak_informative=False)   # SEALED: leak does not generalize here

    return Instance(train=train, validation=validation, holdout=holdout,
                    feature_names=feature_names, leak_feature=leak_feature)
