# SOC L2 Agent - Final Build Audit

## 6X Runtime Recursion Hotfix — October 8, 2026

- Fixed `core/pipeline.py::_finalize_status`. The function was accidentally self-calling instead of stamping `completed_at`, calculating `duration_ms`, and persisting the status.
- This caused a `RecursionError` after approximately 1000 nested calls when pages such as Dashboard, MITRE Center, Analytics, Investigation, Ingestion, Reports, or Settings requested the pipeline in a fresh session.
- The fix restores completion telemetry and uses the same finalization path for Wazuh/Splunk early-return failures.
- Added a regression test so a direct self-recursive `_finalize_status` implementation cannot pass release validation again.
- Verified the real MOCK pipeline path with a lightweight Streamlit session stub: **1000 records analysed**, status `MOCK DATA Loaded`, no pipeline error, completion time recorded.
- Current automated suite: **60/60 PASS**.



## Build focus

This build was reviewed as a complete college-demo package rather than only as a UI patch.
The main priorities were reliable rendering, stable navigation, source ingestion, evidence-safe analysis, code discoverability and clean packaging.

## UI corrections

- Removed raw HTML section wrappers around native Streamlit controls.
- Replaced them with `st.container(border=True)` for stable cards.
- Reworked the presentation layer into a restrained dark enterprise SOC theme with consistent navigation, technical data surfaces and severity-aware visual language.
- Changed KPI layout to responsive two-row groups.
- Changed long MITRE values from cramped metric cards to a two-column table.
- Added stable keys to interactive widgets/charts where useful.
- Added wrapped raw-log/code display to prevent long-line overflow.
- Kept dashboard, Ingestion Center and Investigation navigation consistent.

## Functional checks

- JSON and JSONL loading
- Wazuh structural recognition and normalization
- Splunk export/API parsing
- Common parser/normalizer/detection pipeline
- Severity, risk and confidence separation
- Confirmation status independent from severity
- MITRE source preservation and safe unmapped state
- Related-event investigation logic with bounded 7-day correlation window and explicit correlation reasons
- Optional Groq behavior without an API key
- AI prompt guardrails for missing evidence, confirmation status and MITRE mapping-source fidelity
- Secret redaction in raw telemetry
- PDF generation with long fields and unsupported Unicode
- Empty/malformed-event resilience

## Local verification performed

- Python compilation: PASS
- Automated tests: 60 / 60 PASS
- Standalone MOCK smoke test: PASS
- Wazuh-shaped sample: 1000 records processed, 0 parser/normalizer errors
- Splunk sample: 500 records processed, 0 parser/normalizer errors
- Blue Team sample: 350 records processed, 0 parser/normalizer errors
- PDF generation: PASS
- PDF rendered/visually inspected: PASS
- Streamlit render-contract smoke test with a local API stub: PASS
- Open Investigation button flow: PASS
- ZIP integrity: verified before delivery
- No `.env`, `__pycache__` or `.pyc` files included in the final package

## Viva navigation

Use `CODE_MAP.md` to immediately locate Wazuh, Splunk, Parser, Normalizer, Detection, Severity/Risk/Confidence, MITRE, Investigation, Groq, PDF, Security and UI code.


## Release cross-check

- Wazuh-shaped MOCK: 1,000 / 1,000 processed, 0 parser errors, 0 normalizer errors.
- Wazuh-shaped MOCK severity profile: 125 High, 750 Medium, 125 Low, 0 Critical.
- Splunk sample: 500 / 500 processed, 0 parser errors, 0 normalizer errors.
- Blue Team sample: 350 / 350 processed, 3 Critical records.
- Alert search verification: incident ID `1790411382.000997` -> 1 result; rule `80700` -> 125 results.
- Related-event correlation is bounded to 7 days and exposes an explicit reason.
- MITRE wording no longer claims source-supplied mapping when the final mapping state is unmapped.
- AI prompts are evidence-grounded and preserve Unconfirmed state / source mapping.
- PDF long-token timestamp rendering and missing-field handling covered by tests.
- Release package contains no `.env`, API key, `__pycache__` or `.pyc`.


## Saturday-ready hardening

The final audit build was reviewed once more for small reliability gaps. The latest hardening covers flattened Wazuh/OpenSearch field recognition, real MOCK file validation during connection testing, Normal-event exclusion from the Investigation selector, related events in generated incident PDFs, broader secret redaction, dependency-aware Windows launchers, and explicit handling of the rule-only Blue Team dataset.


## Latest micro-hardening pass (2026-10-08)

- Wazuh `data.path` is extracted as Filename when the source supplies it.
- Supplied URLs now populate URI Path and URI Query evidence fields without inventing data.
- Stringified JSON, key/value text, session IDs and common cookie/token fields are redacted before UI/PDF/AI use.
- Related-event string logs use the same redaction boundary.
- Alert Queue is newest-first after filters.
- Ingestion reads current status after loading so the first render does not show a stale status snapshot.
- Investigation AI services use the shared project-root settings loader; no credentials were changed.
- Wazuh informational classification is based on the configured low-level threshold, not on MITRE presence.
- Lateral Movement rule metadata is aligned with its numeric 9.2 risk score and Critical band.
- Added regression coverage for the new extraction, redaction, correlation, sorting and detection behavior.
- Existing report/PPT deliverables under `docs/` were not modified in this pass.
