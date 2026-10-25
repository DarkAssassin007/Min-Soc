# Mini SOC — Machine learning

The ML subsystem is deliberately split in two: `ml/` trains and evaluates
models offline; the backend only **loads versioned artifacts** and never trains
at request time. A deployed instance always knows which model produced a score.

## 1. Feature contract

`FEATURE_ORDER` (14 behavioural features per source entity over a 5-minute
window) is defined once in `backend/app/processors/feature_engineering.py` and
re-exported by `ml/features.py`. Both training and the registry record the order,
so a mismatch is detectable instead of silently corrupting scores:

```text
connection_count, unique_destination_ports, unique_destination_ips,
failed_connections, dns_requests, unique_dns_queries, auth_failures,
bytes_total, packets_total, bytes_per_second, packets_per_second,
avg_connection_duration_ms, unique_protocols, events_per_minute
```

## 2. Dataset

`ml/features.py::build_synthetic_dataset` generates the labelled lab dataset:

* normal traffic (60%): typical hosts — ~12 connections, a few hundred KB,
  DNS activity — plus **40% sparse windows** (new/idle hosts with 1–8
  connections) so the model does not flag every entity's first events as
  anomalous (cold-start noise; verified 37.5% → 0% false positives on benign
  lab traffic after retraining);
* attacks (5 scenarios × N samples): port scan, brute force, connection flood,
  DNS anomaly, volume anomaly.

`Dataset.split()` produces the stratified train/validation split used by
evaluation. `ml/dataset.py` also supports `--source database`, exporting
feature vectors recomputed from stored events for retraining on real traffic.

## 3. Training

```bash
# Isolation Forest baseline on the lab dataset (the shipped model)
.venv/Scripts/python.exe -m ml.train --baseline --report logs/training-report.json

# Other supported estimators
.venv/Scripts/python.exe -m ml.train --algorithm local_outlier_factor --source synthetic
.venv/Scripts/python.exe -m ml.train --algorithm one_class_svm
```

Training is **unsupervised on normal samples only** (that is how anomaly
detection should work); the labelled hold-out is used strictly for evaluation.
The decision threshold is a configurable percentile of normal validation scores
(default 5th percentile). The joblib payload contains the fitted estimator,
scaler, threshold, algorithm, feature order, version and timestamp.

## 4. Evaluation (shipped baseline `baseline_isolation_forest:v2-20261003`)

| metric | value |
|--------|-------|
| precision | 0.943 |
| recall | 1.000 |
| F1 | 0.971 |
| false-positive rate | 0.0305 |
| false-negative rate | 0.000 |
| ROC AUC | 0.9996 |
| threshold | -0.56870 |
| inference latency (single call) | ~11 ms |

Full per-scenario rates and confusion matrix: `logs/training-report.json`.

## 5. Model registry and deployment

`backend/app/detection/anomaly/registry.py` reads
`ml/artifacts/manifest.json` (active version, models, metrics, threshold,
feature order). `POST /api/v1/models/activate` (ADMIN) switches versions;
`GET /api/v1/models` lists them. If no artifact exists, a bundled baseline is
trained once on first start. Every inference is stored in `model_predictions`
(score, threshold, decision, features, latency) for drift analysis.

## 6. Inference performance

scikit-learn spends ~10 ms **per scoring call** dispatching its parallel jobs,
regardless of how many samples are passed. Two changes removed that bottleneck:

1. the pipeline scores the whole batch in one `score_samples` call (see
   architecture §4) — detection stage latency dropped from 26.8 ms to 0.21 ms
   per event and end-to-end throughput rose from 26.8 to ~210 events/s;
2. the detector derives the anomaly decision from the estimator's `offset_`
   instead of issuing a second `predict` call, and supports
   One-Class SVM/LoF style models via `decision_function`.

Each `AnomalyResult` reports its share of the batch time, so per-event latency
metrics stay comparable.

## 7. Retraining runbook

1. Export real features if available: `python -m ml.train --source database`.
2. Train with an explicit version: `--version v3-YYYYMMDD`.
3. Inspect `logs/training-report.json` (precision/recall/FPR, per-scenario).
4. Activate the new version through the API (or restart so the active manifest
   entry is loaded), then compare `model_predictions` drift over a day.
5. Keep the previous artifact: activation is reversible from the manifest.
