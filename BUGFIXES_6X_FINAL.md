# 6X Final Runtime Bugfix

## Root Cause
`core/pipeline.py` contained an accidental direct recursive call inside `_finalize_status()`. Every pipeline load that reached status finalization re-entered the same function until Python raised `RecursionError`.

## Fixed Behavior
`_finalize_status()` now:

1. records `completed_at`;
2. calculates `duration_ms` from `time.perf_counter()`;
3. persists the status through `_set_status()`.

Wazuh and Splunk early-return paths now use the same finalization path, so the status panel also receives completion telemetry on connection failure.

## Regression Protection
A new test in `tests/test_project_integrity.py` parses `core/pipeline.py` and asserts that `_finalize_status()` does not call itself and continues to persist completion fields.

## Validation
- `python -m pytest -q` → **60 passed**
- `python -m compileall -q .` → **PASS**
- Release validation → **PASS**
- Lightweight runtime pipeline smoke → **1000 MOCK records analysed, no pipeline error**

## Important
The recursive helpers in `core/security.py`, `core/telemetry_quality.py`, `services/wazuh_service.py`, and `pages/Investigation.py` are intentional data-structure traversal helpers, not the same bug. JSON/Python event structures cannot create the self-referential object cycle that would be required for the normal input path, and their recursion has an actual terminating branch.
