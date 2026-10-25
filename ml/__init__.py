"""Mini SOC machine-learning training pipeline.

This package is intentionally separate from the deployed backend:

* ``ml.train``      - dataset -> clean -> split -> train -> evaluate -> register
* ``ml.dataset``    - dataset construction (database export or synthetic lab)
* ``ml.features``   - the canonical feature contract shared with the backend
* ``ml.evaluate``   - precision/recall/F1/FPR/FNR/ROC-AUC + inference latency

The backend only ever *loads* the resulting versioned artifact, so retraining
can never change the behaviour of a running SOC by accident.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "1.0.0"
