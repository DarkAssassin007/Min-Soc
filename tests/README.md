# tests/

This directory is part of the required repository layout (master spec §30).
The automated suites live next to the code they exercise:

| suite | location | what it covers |
|-------|----------|----------------|
| backend unit + integration | `backend/tests/` (10 files, 236 tests) | config, collectors, processors, detection, pipeline, alerts/incidents, API, security, ML |
| dashboard | `frontend/src/**/*.test.{js,jsx}` (vitest, 14 tests) | formatting utilities and shared UI state components |
| end-to-end lab validation | `scripts/lab_validation.py` | controlled attack + benign scenarios through the real runtime (`logs/validation-report.json`) |
| performance benchmark | `scripts/benchmark_pipeline.py` | throughput, latency, CPU/memory (`logs/benchmark-report.json`) |

Run everything on Windows:

```bat
scripts\run_tests.bat        :: backend + dashboard suites
scripts\validate_lab.bat     :: end-to-end detection validation
scripts\benchmark.bat 4000   :: throughput / latency benchmark
```

Or directly:

```bash
cd backend && ../.venv/Scripts/python.exe -m pytest -q     # 236 passed
cd frontend && npm test                                     # 14 passed
```
