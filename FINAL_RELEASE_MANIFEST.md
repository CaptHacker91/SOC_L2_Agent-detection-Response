# FINAL MASTER RELEASE MANIFEST

Release: `SOC_L2_Agent_FINAL_MASTER_120X_ENHANCED`
Build ID: `SOC-2026.10.08-MASTER`
Application version: `1.1`
Telemetry schema: `1.2`
Case store schema: `1.1`

## Core deliverables
- `app.py` — SOC command console
- `core/` — ingestion, normalization, pipeline, telemetry quality, UI, diagnostics and visualization
- `engine/` — detection, severity, MITRE and alert-triangle logic
- `services/` — Wazuh/Splunk/AI/case/report/correlation services
- `pages/` — Dashboard-linked operational centers for Ingestion, Investigation, Analytics, Detection Engineering, MITRE, IOC, Reports, Audit and Settings
- `rules/detection_rules.json` — versioned detection configuration
- `data/` — supplied telemetry fixtures
- `tests/` — regression and release validation suite
- `docs/` — existing report and presentation assets
- `ARCHITECTURE.md`, `DEMO_GUIDE.md`, `VIVA_GUIDE.md`, `MASTER_IMPLEMENTATION_STATUS.md`, `FINAL_MASTER_ROADMAP.md`

## Implemented product improvements
Persistent case lifecycle, analyst assignment and decision, case history/audit, evidence completeness, event fingerprints and duplicate signals, rule explainability, Wazuh control wiring, real pagination, bounded correlation modes, risk-confidence analytics, MITRE and IOC centers, reports/evidence packages, safe runtime diagnostics, schema inspection, event replay, structured optional AI assistance and explicit human-decision boundaries.

## Verification
- 60 automated tests: PASS
- Final dataset validation: PASS
- Python compile validation: PASS
- Secret/config packaging check: PASS
- Temporary state/cache files excluded from final archive
- Live Streamlit browser smoke test: not performed in container because Streamlit package is unavailable there

## Distribution boundary
`.env` is intentionally excluded. Users should copy `.env.example` to `.env` locally and configure only required integrations.


## Current UI enhancement
- UI: 4X executive presentation layer with persistent DESAI creator credit and local photo-ready identity module
