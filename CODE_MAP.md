# SOC L2 Agent — Code Map

Use this file during the college viva to locate each major implementation area quickly.

## 1. End-to-End Flow

```text
MOCK / WAZUH / SPLUNK
        |
      Parser
        |
    Normalizer
        |
 Data Quality / Fingerprint
        |
    Detection Engine
        |
Severity / Risk / Confidence
        |
 Correlation / Clustering
        |
      MITRE
        |
 Investigation / Evidence
        |
 Optional AI Assistance
        |
 Human Analyst Decision
        |
 Case Store / Audit
        |
 Report / Evidence Package
```

## 2. Professor Viva Map

| Professor asks... | File | Main symbol / area |
|---|---|---|
| Where does data come from? | `core/data_source.py` | `get_data_source()` |
| Where is configuration loaded? | `core/config.py` | `load_settings()` |
| Where is JSON / JSONL loaded? | `core/file_loader.py` | `FileLoader.load()` |
| Where is event type detected? | `core/parser.py` | `DetectionParser` |
| Where is common normalization done? | `core/normalizer.py` | `DataNormalizer.normalize()` |
| Where are quality/fingerprint fields added? | `core/telemetry_quality.py` | `enrich_dataframe()` |
| Where is the pure processing pipeline? | `core/analysis.py` | `analyze_events()` |
| Where is source/session orchestration handled? | `core/pipeline.py` | `refresh_data()` / `get_wazuh_controls()` |
| Where are detection rules applied? | `engine/detection_engine.py` | `DetectionEngine.analyze()` |
| Where are rules configured? | `rules/detection_rules.json` | JSON rule definitions |
| Where are severity/risk/confidence calculated? | `engine/severity_engine.py` | `SeverityEngine.calculate()` |
| Where is confirmation separated? | `engine/alert_triangle.py` | `AlertTriangle.generate()` |
| Where is MITRE mapping done? | `engine/mitre_mapper.py` | `MitreMapper.map()` |
| Where are related events/correlation found? | `services/incident_context.py` | `find_related_events()` |
| Where is persistent case state stored? | `services/case_store.py` | `get_or_create_case()` / `update_case()` |
| Where is the Investigation UI? | `pages/Investigation.py` | `main()` |
| Where is centralized analytics? | `pages/Analytics.py` | `main()` |
| Where is MITRE center? | `pages/MITRE_Center.py` | `main()` |
| Where is IOC extraction/relationship view? | `pages/IOC_Intelligence.py` | `main()` |
| Where are reports centralized? | `pages/Reports.py` | `main()` |
| Where is persistent audit history? | `pages/Audit_Log.py` | `main()` |
| Where are safe environment diagnostics? | `pages/Settings.py` | `main()` |
| Where is detection rule replay? | `pages/Detection_Engineering.py` | `main()` |
| Where is Groq AI analysis? | `services/llm_service.py` | `LLMService.investigate()` |
| Where is the incident chatbot? | `services/chatbot_service.py` | `ChatbotService.ask()` |
| Where is PDF generation? | `services/report_service.py` | `generate_pdf()` |
| Where is the portable incident package? | `services/report_service.py` | `build_incident_package()` |
| Where are secrets redacted? | `core/security.py` | `redact_object()` / `safe_json()` |
| Where is Wazuh API/Indexer handling? | `services/wazuh_service.py` | `test_connection()` / `fetch_alerts()` |
| Where is Splunk handling? | `core/splunk_loader.py` | `test_connection()` / `load()` |
| Where is the dashboard? | `app.py` | `main()` |
| Where is shared visual styling? | `core/ui.py` | `apply_theme()` / navigation helpers |
| Where are charts? | `core/visualization.py` | chart helper functions |
| Where are tests? | `tests/` | unit/integration/static tests |

## 3. Navigation

- `app.py` — Dashboard / alert queue / telemetry explorer.
- `pages/Ingestion.py` — Source health, Wazuh controls, reconciliation and data quality.
- `pages/Investigation.py` — Evidence, explainability, correlation, case management, AI, report and history.
- `pages/Analytics.py` — Risk, confidence, severity, trend, tactic and rule coverage analytics.
- `pages/MITRE_Center.py` — Technique/tactic mapping and unmapped queue.
- `pages/IOC_Intelligence.py` — IOC inventory from observed telemetry only.
- `pages/Reports.py` — Persistent cases and report/evidence-package export.
- `pages/Audit_Log.py` — Persistent analyst activity history.
- `pages/Settings.py` — Safe provider/runtime diagnostics.
- `pages/Detection_Engineering.py` — Rule coverage and controlled replay.

## 4. Trust / Security Boundaries

- MOCK is explicitly labeled as deterministic demo telemetry.
- Wazuh/Splunk connectivity is never fabricated.
- Missing fields remain `Not available in supplied telemetry`.
- Correlation is time-bounded and displays its reason/confidence.
- Detection, severity, risk and confidence do not equal confirmation.
- AI is optional, evidence-grounded and advisory.
- Analyst decision is stored separately from automated detection.
- Secrets are excluded from rendered settings and redacted on export.
- SQLite state is local prototype persistence, not an enterprise SIEM audit replacement.

- Dataset-grounded global AI SOC Assistant: `services/chatbot_service.py` (local deterministic fallback + optional Groq layer).
