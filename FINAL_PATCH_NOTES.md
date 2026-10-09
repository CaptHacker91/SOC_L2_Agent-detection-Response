# SOC L2 Agent - Final Patch Notes

## Changes made

1. MITRE wording consistency
   - Removed the detection-stage message that could claim MITRE information was supplied by the event source when the final investigation view showed the incident as unmapped.
   - The Investigation MITRE section now explicitly states that it uses supplied telemetry, explicit configured mappings, or a safe unmapped state.

2. Related-event correlation hardening
   - Related events are now limited to a 7-day correlation window.
   - Correlation remains evidence-based: same source IP OR same host + rule ID.
   - Results are ordered by temporal proximity and then correlation strength.
   - The UI now shows the exact correlation reason and the detection reason separately.

3. AI evidence guardrails
   - AI prompts explicitly treat "Not available in supplied telemetry" as unavailable and forbid inference.
   - AI must preserve the supplied MITRE technique and mapping source.
   - AI must not turn an Unconfirmed incident into a confirmed compromise.
   - Related events are treated as context, not proof of compromise.

4. Tests and documentation
   - Added regression tests for the MITRE wording guardrail and time-bounded correlation.
   - Updated README, CODE_MAP and FINAL_AUDIT to describe the current correlation and AI guardrails.

## Validation completed

- Python compile validation: PASS
- Automated unit tests: 47 / 47 PASS (before the latest micro-hardening pass)
- MOCK smoke test: PASS (1,000 records processed)
- Selected-event cross-check: PASS
- Related-event correlation check: PASS
- No API keys or real .env file included in this package


5. Final release polish
   - Added a testable Alert Queue filter helper so ID/rule/threat searches are directly regression-tested.
   - Added an explicit Critical-threshold note in the dashboard when the current dataset has zero Critical detections.
   - Added `tests/test_release_validation.py` and `scripts/final_validation.py` for cross-dataset and end-to-end checks.
   - Refreshed README and audit counts to the 47-test suite at that release stage.


6. Saturday documentation polish
   - Aligned README navigation text with the exact `Open Investigation` button label.
   - Updated manual setup commands to use the correct PowerShell activation syntax.
   - Kept final report/presentation PDFs trackable under `docs/` while continuing to ignore other generated PDFs.


7. Final micro-hardening pass
   - Wazuh `data.path` now maps to normalized Filename.
   - Wazuh URL values now populate URI Path / URI Query from the supplied URL only.
   - Stringified JSON, query-string and session identifiers are redacted before UI/report/AI use.
   - Related-event raw strings use the same redaction boundary as structured events.
   - Alert Queue is ordered newest-first after filtering.
   - Ingestion status is read after the pipeline load, avoiding a stale first-render status.
   - Investigation AI services now use the shared project-root settings loader without changing keys.
   - Low-level Wazuh informational classification no longer changes based on MITRE presence.
   - Lateral Movement rule metadata now aligns with its 9.2 risk score and Critical band.
   - Optional AI chat history and generated responses receive the same secret-redaction boundary.
   - Added regression tests for each new safety/data/UI behavior.


Latest validation after micro-hardening: **60 / 60 automated tests PASS**, compile validation PASS, MOCK smoke test PASS, release validation PASS.

- Extended redaction to scalar incident-context fields and direct Investigation evidence display; added regression coverage.
- Direct Investigation selector now uses newest-first ordering too.


8. Final SOC UI redesign
   - Replaced the previous light/admin-style presentation with a dark enterprise SOC visual system across Dashboard, Ingestion Center and Investigation.
   - Added a consistent navy/charcoal palette, cyan/blue primary accents, fixed Critical/High/Medium/Low severity colors and a restrained AI purple accent.
   - Added SOC-style status badges, operational header strip, pipeline visualization, newest-first latest-alert feed, technical telemetry search and an analyst workspace.
   - Updated Plotly charts to dark SOC surfaces with consistent grid, typography, hover and severity styling.
   - Kept the existing ingestion, detection, severity/risk, MITRE, correlation, AI and PDF logic unchanged; this pass is presentation-layer focused.
   - Kept the final report/presentation files and all supplied datasets unchanged.

Latest validation after UI redesign: **60 / 60 automated tests PASS**, Python compile validation PASS, MOCK smoke/release validation PASS.
