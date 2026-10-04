# SOC L2 Agent - Code Map

Use this file during the college viva to locate every major part of the project quickly.
The project keeps **presentation**, **pipeline**, **detection**, **integration**, and **reporting** code separate so the flow is easy to explain.

## 1. End-to-End Flow

```text
MOCK / WAZUH / SPLUNK
        |
      Parser
        |
    Normalizer
        |
    Detection
        |
Severity / Risk / Confidence
        |
      MITRE
        |
  Investigation
     /       \
  Groq AI     PDF
```

## 2. Professor Viva Map

| Professor asks... | File | Main symbol / area |
|---|---|---|
| Where does data come from? | `core/data_source.py` | `get_data_source()` |
| Where is configuration loaded? | `core/config.py` | `load_settings()` |
| Where is JSON / JSONL loaded? | `core/file_loader.py` | `FileLoader.load()` |
| Where is event type detected? | `core/parser.py` | `DetectionParser._categorize()` |
| Where is Wazuh recognized structurally? | `services/wazuh_service.py` | `looks_like_wazuh_event()` |
| Where is Wazuh data extracted? | `services/wazuh_service.py` | `normalize_wazuh_alert()` |
| Where is common normalization done? | `core/normalizer.py` | `DataNormalizer.normalize()` |
| Where is the pure processing pipeline? | `core/analysis.py` | `analyze_events()` |
| Where is Streamlit orchestration/state handled? | `core/pipeline.py` | `refresh_data()` / `load_pipeline()` |
| Where are detection rules applied? | `engine/detection_engine.py` | `DetectionEngine.analyze()` |
| Where are rules configured? | `rules/detection_rules.json` | JSON rule definitions |
| Where are severity/risk/confidence calculated? | `engine/severity_engine.py` | `SeverityEngine.calculate()` |
| Where is confirmation separated from severity? | `engine/alert_triangle.py` | `AlertTriangle.generate()` |
| Where is MITRE mapping done? | `engine/mitre_mapper.py` | `MitreMapper.map()` |
| Where are related events found? | `services/incident_context.py` | `find_related_events()` |
| Where is the Investigation UI? | `pages/Investigation.py` | `main()` |
| Where is Groq AI analysis? | `services/llm_service.py` | `LLMService.investigate()` |
| Where is the Groq chatbot? | `services/chatbot_service.py` | `ChatbotService.ask()` |
| Where is PDF generation? | `services/report_service.py` | `generate_pdf()` |
| Where are secrets redacted? | `core/security.py` | `redact_object()` / `safe_json()` |
| Where is Wazuh connection/fetch handled? | `services/wazuh_service.py` | `test_connection()` / `fetch_alerts()` |
| Where is Splunk connection/search handled? | `core/splunk_loader.py` | `test_connection()` / `load()` |
| Where is dashboard UI? | `app.py` | `main()` |
| Where is shared UI styling/navigation? | `core/ui.py` | `apply_theme()` / `page_header()` |
| Where are dashboard charts? | `core/visualization.py` | `severity_donut()` / `detection_bar()` / `top_techniques()` / `alert_trend()` |
| Where is the ingestion screen? | `pages/Ingestion.py` | `main()` |
| Where are automated tests? | `tests/` | unit tests + `smoke_test.py` |

## 3. UI Navigation

- `app.py` — dashboard, overview charts, alert filters and incident selection.
- `pages/Ingestion.py` — source status, connection test, ingestion and preview.
- `pages/Investigation.py` — incident evidence, MITRE, related events, recommendations, AI, PDF and chat.
- `core/ui.py` — shared professional theme and layout helpers.
- `.streamlit/config.toml` — light theme and safe local Streamlit settings.

## 4. Why the UI Uses Native Containers

Earlier versions mixed raw HTML `<div>` tags with native Streamlit components. That can create malformed DOM/layout behavior and visual overlays after reruns or on smaller screens.
The current build uses `st.container(border=True)` for section cards and keeps custom HTML limited to the CSS/style layer.

## 5. Evidence and Trust Rules

- MOCK is always labelled as demo data.
- Real Wazuh/Splunk connectivity is never faked.
- Missing telemetry is displayed as `Not available in supplied telemetry`.
- High/Critical severity does not automatically mean confirmed compromise.
- AI output is advisory only and grounded in the selected incident context.
