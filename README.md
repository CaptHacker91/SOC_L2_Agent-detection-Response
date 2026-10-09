# SOC L2 Agent - Detection & Response Dashboard

A modular Streamlit-based Security Operations Center (SOC) Level-2 demonstration project. It loads telemetry from **MOCK**, **WAZUH**, or **SPLUNK**, normalizes the data into one event structure, runs evidence-based detections, calculates severity/risk/confidence, maps MITRE ATT&CK when supported, provides an Investigation page, optional Groq-assisted analysis, and generates a PDF incident report.

## 1. Project Overview

The project is designed for a college Blue Team / SOC demonstration. The default mode is **MOCK**, so the complete application can run without Wazuh, Splunk, or Groq.

Important evidence rule: a detection, high severity, or AI statement is not automatically a confirmed compromise. The application keeps **severity**, **risk**, **confidence**, and **confirmation status** separate.

## 2. Main Features

- MOCK mode using the supplied sample Wazuh-shaped telemetry
- Optional real Wazuh Server API + Wazuh Indexer integration
- Optional real Splunk REST search integration
- One common parser -> normalizer -> detection -> risk/severity -> MITRE -> investigation pipeline
- Evidence-based detection rules
- Separate severity, risk score and confidence
- MITRE mapping with mapping source and an explicit unmapped state
- Investigation page with raw telemetry, related events and recommendations
- Optional Groq AI analysis and incident-aware chatbot
- Secret-safe PDF reports with wrapping and page breaks
- Safe handling of missing fields, malformed records and unavailable services
- Tests and a standalone smoke test

## 2.1 Final Hacker-Terminal UI

The final release uses a dark hacker-terminal / SOC command-console presentation layer while preserving the evidence-first backend flow. The Dashboard includes threat KPIs, risk/confidence/console-health indicators, interactive analytics and a live-style demo stream. The Alert Center supports search plus severity/source/MITRE/status filtering. The Investigation Console includes normalized evidence, redacted raw data, IOC snapshot, MITRE context, 7-day related-event correlation, recommendations, analyst decision and notes, a session audit trail, optional AI/chat and PDF export. The Ingestion Control Room exposes source health, diagnostics and pipeline preview. A Presentation Mode is available for the college demo.

## 3. Architecture

```text
MOCK / WAZUH / SPLUNK
          |
          v
       PARSER
          |
          v
      NORMALIZER
          |
          v
     DETECTION ENGINE
          |
          v
 SEVERITY / RISK / CONFIDENCE
          |
          v
      MITRE MAPPER
          |
          v
      INVESTIGATION
          |
          +------> Optional Groq AI
          |
          v
       PDF REPORT
```

## 4. Folder Structure

```text
SOC_L2_Agent/
├── app.py                       # Main Streamlit dashboard
├── .env.example                 # Safe configuration template
├── requirements.txt             # Python dependencies
├── README.md
├── core/
│   ├── config.py                # Central environment configuration
│   ├── models.py                # Normalized event contract
│   ├── security.py              # Secret redaction helpers
│   ├── file_loader.py           # JSON / JSONL / local mock loading
│   ├── parser.py                # Event categorization
│   ├── normalizer.py            # Common event normalization
│   ├── analysis.py              # Pure processing pipeline
│   ├── data_source.py           # Source factory
│   ├── splunk_loader.py         # Splunk REST client
│   └── pipeline.py              # Streamlit session orchestration
├── engine/
│   ├── detection_engine.py      # Detection rules / evidence logic
│   ├── severity_engine.py       # Severity, risk and confidence
│   ├── mitre_mapper.py          # MITRE ATT&CK mapping
│   └── alert_triangle.py        # Triage / confirmation separation
├── services/
│   ├── wazuh_service.py         # Wazuh API + Indexer integration
│   ├── incident_context.py      # Investigation context + correlation
│   ├── llm_service.py           # Optional Groq investigation report
│   ├── chatbot_service.py       # Optional Groq incident chatbot
│   └── report_service.py        # PDF report generation
├── pages/
│   └── Investigation.py         # Investigation UI
├── rules/
│   └── detection_rules.json     # Configurable detection/risk metadata
├── data/
│   ├── wazuh_events.jsonl        # Wazuh-shaped mock security telemetry
│   ├── splunk_export.jsonl       # Sample Splunk export
│   └── BLUE_TEAM_DEFENSE_DATASET.jsonl
├── n8n/
│   └── docker-compose.yml       # Optional n8n helper
└── tests/                       # Automated local tests
```

## 5. Code Map / Viva Navigation

See `CODE_MAP.md` for a quick file-by-file map of where Wazuh, Splunk, parser, normalizer, detection, severity, MITRE, Investigation, AI and PDF code lives.

## 6. Requirements

- Windows 10/11 or Linux/macOS
- **Python 3.13**
- Internet access is only needed to install packages and when using real Splunk/Wazuh/Groq services.
- Wazuh, Splunk and Groq are optional at runtime when using MOCK mode.

## 7. Windows Installation

Open the project folder in VS Code PowerShell:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Create the local environment file:

```powershell
Copy-Item .env.example .env
```

For the first demo, keep:

```text
DATA_SOURCE=MOCK
```

## 8. Run in MOCK Mode

The default mock source is `data/wazuh_events.jsonl`, which contains Wazuh-shaped sample records. They are displayed as **MOCK**, never as a live Wazuh connection.

Run:

```powershell
python -m streamlit run app.py
```

Expected behavior:

- dashboard opens without Wazuh
- security detections appear from local sample data
- data source shows **MOCK**
- Investigation page works through the Alerts selector
- PDF report works
- AI features show an unavailable message when `GROQ_API_KEY` is empty

## 9. Use a Different Mock Dataset

Change `.env`:

```text
MOCK_DATA_PATH=data/BLUE_TEAM_DEFENSE_DATASET.jsonl
```

or:

```text
MOCK_DATA_PATH=data/splunk_export.jsonl
```

The loader supports JSON, JSONL and common wrapped export formats.

## 10. Wazuh Mode

Set:

```text
DATA_SOURCE=WAZUH
WAZUH_HOST=your-wazuh-host
WAZUH_API_PORT=55000
WAZUH_API_USER=your-api-user
WAZUH_API_PASSWORD=your-api-password
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-indexer-user
WAZUH_INDEXER_PASSWORD=your-indexer-password
WAZUH_VERIFY_SSL=true
```

The Wazuh integration uses the Server API for authentication and the Indexer for alert search. The application never invents a successful connection: if a component is unavailable, the UI reports the status and safely keeps previously loaded data when possible.

### Self-signed certificates

For a controlled local Wazuh installation using self-signed certificates, you may set:

```text
WAZUH_VERIFY_SSL=false
```

Use `true` for normal verified TLS deployments.

## 11. Splunk Mode

Set:

```text
DATA_SOURCE=SPLUNK
SPLUNK_HOST=your-splunk-host
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-token
SPLUNK_SEARCH_QUERY=search index=main | head 100
SPLUNK_VERIFY_SSL=true
```

The search results are sent through the same parser and normalizer used by the other sources.

## 12. Groq / AI Setup

AI is optional.

Leave the key blank for a no-AI demo:

```text
GROQ_API_KEY=
```

To enable AI, add your own key:

```text
GROQ_API_KEY=your-real-key
GROQ_MODEL=openai/gpt-oss-20b
```

The configured model is intentionally environment-driven. Verify model availability in your Groq account if the model catalogue changes.

AI output is always labelled **AI-Assisted Analysis** and is grounded in the selected incident context.

## 13. n8n Setup (Optional)

The SOC application does not require n8n for MOCK/Wazuh/Splunk/AI operation.

For an optional local automation demo:

```powershell
cd n8n
docker compose up -d
```

Open:

```text
http://localhost:5678
```

Create the local owner account through n8n's first-run setup. Do not add passwords or API keys to `docker-compose.yml`.

## 14. Testing

Run the standard library test suite:

```powershell
python -m unittest discover -s tests -p "test_*.py"
```

Run the standalone smoke test:

```powershell
python tests/smoke_test.py
```

## 15. Demo Reliability Notes

- In MOCK mode, **Test Source Connection** validates that the configured JSON/JSONL file can actually be parsed and reports the readable record count; it is not only a file-existence check.
- The demo launchers skip dependency installation when the required packages are already present, so a prepared laptop does not need Internet access just to start the app.
- After editing `.env`, restart Streamlit so the new configuration is loaded cleanly.

## 16. Supplied Dataset Notes

`BLUE_TEAM_DEFENSE_DATASET.jsonl` is a **synthetic detection-rule dataset**, not a full host/network telemetry feed. Its rows intentionally contain rule/signature/tool/MITRE fields but do not contain timestamps, IP addresses or process/file telemetry. The application therefore does not invent those missing values.

## 17. What the Detection Status Means

- **Normal**: no configured security detection evidence matched.
- **Anomaly**: evidence matched a detection rule/pattern and should be reviewed.
- **Unconfirmed**: the current telemetry does not independently prove compromise.

High/Critical severity changes triage priority; it does **not** automatically change confirmation status.

For configured synthetic rules, the numeric **risk score is the source of truth for the displayed severity band** (for example, 9.2/10 is displayed as Critical). The descriptive `severity` value in `rules/detection_rules.json` is reference metadata and does not override the numeric risk band.

## 18. Investigation Page

Open the **Alerts** tab, select an alert, then press **Open Investigation**. The page also has its own incident selector, so it can be used directly.

The page shows:

- alert metadata
- Wazuh/Splunk/Mock source
- host/agent information
- source and destination IP
- username
- rule ID/level/groups
- detection reason
- severity/risk/confidence
- MITRE mapping and mapping source
- process/command/URL/hash
- redacted raw telemetry
- related events (same source IP or same host + rule ID within a 7-day correlation window)
- investigation/containment/remediation suggestions
- optional AI analysis
- downloadable PDF report

Missing information is displayed as:

```text
Not available in supplied telemetry
```

## 19. Security Notes

- Never commit `.env`.
- Never place real API keys or passwords in `.env.example`.
- Never put Wazuh/Splunk credentials in source files.
- Raw telemetry shown in the Investigation page and sent to optional AI is redacted for common credential/token patterns.
- Connection errors are shown without printing passwords/tokens.
- Use TLS verification in normal deployments.
- Do not treat AI output as evidence.
- AI must preserve `Not available in supplied telemetry`, the reported confirmation status, and the supplied MITRE mapping source; it must not invent missing evidence.
- Related events are contextual correlation signals only; the UI shows the correlation reason used for each result.
- Do not treat a rule match as proof of compromise without corroboration.

## 20. Phone / Team Member Demo

To allow a team member's phone to view the Streamlit demo while connected to the same Wi-Fi network:

```powershell
python -m streamlit run app.py --server.address 0.0.0.0
```

Find the laptop IPv4 address:

```powershell
ipconfig
```

Then open:

```text
http://YOUR-LAPTOP-IP:8501
```

Windows Firewall may ask for permission the first time. Only allow the port on a trusted network.

## 21. Common Errors

### `ModuleNotFoundError`

Activate the virtual environment and run:

```powershell
pip install -r requirements.txt
```

### No MOCK events

Check:

```text
MOCK_DATA_PATH=data/wazuh_events.jsonl
```

and verify the file exists.

### Wazuh authentication failed

Check the Server API credentials separately from Indexer credentials.

### Wazuh certificate error

Check `WAZUH_VERIFY_SSL`. For a local self-signed lab only, set it to `false`.

### Splunk authentication failed

Check `SPLUNK_TOKEN` and the Splunk management/search port.

### AI unavailable

This is normal when `GROQ_API_KEY` is empty. Core detection and investigation do not depend on AI.

### PDF generation failure

Re-run the local tests. The report generator wraps long tokens and converts unsupported Unicode characters safely for the built-in PDF font.

## 22. College Demonstration Flow

1. Start the app in MOCK mode.
2. Point out the **MOCK / DEMO DATA** source indicator.
3. Show the alert queue and severity/risk/confidence values.
4. In **Alerts**, select an incident and click **Open Investigation**.
5. Show the normalized fields and MITRE mapping source.
6. Expand the redacted raw event.
7. Show related events and recommendations.
8. Generate/download the PDF.
9. Explain that AI is optional and does not replace telemetry evidence.
10. For source-code questions, use the module names listed in the folder structure above.

## 23. Important Code Locations for Viva

| Functionality | File |
|---|---|
| Main Dashboard | `app.py` |
| Configuration | `core/config.py` |
| Data Source Selection | `core/data_source.py` |
| JSON / JSONL Loader | `core/file_loader.py` |
| Event Categorization | `core/parser.py` |
| Normalization | `core/normalizer.py` |
| Complete Core Pipeline | `core/analysis.py` / `core/pipeline.py` |
| Wazuh Integration | `services/wazuh_service.py` |
| Splunk Integration | `core/splunk_loader.py` |
| Detection Logic | `engine/detection_engine.py` |
| Severity / Risk / Confidence | `engine/severity_engine.py` |
| MITRE Mapping | `engine/mitre_mapper.py` |
| Confirmation/Triage | `engine/alert_triangle.py` |
| Investigation Context | `services/incident_context.py` |
| Investigation UI | `pages/Investigation.py` |
| Groq AI Report | `services/llm_service.py` |
| Groq Chatbot | `services/chatbot_service.py` |
| PDF Report | `services/report_service.py` |
| Detection Configuration | `rules/detection_rules.json` |

## 24. Security Boundary

This is a college demonstration/analysis tool. It is not a replacement for a production SOC platform. Real Wazuh/Splunk connections should be used only with authorized infrastructure and appropriate credentials.

## UI/Demo Troubleshooting

### Text overlay / overlapping UI
The interface uses native `st.container(border=True)` sections rather than raw HTML wrappers around Streamlit widgets. This keeps headings, tables, buttons and reruns in separate stable layout blocks.


### Dashboard loads but charts are missing
Run `pip install -r requirements.txt`. Plotly is an explicit runtime dependency for the interactive visualization layer.

### Investigate button/navigation does not open the incident
Use the **Alerts** tab on the dashboard, select an alert and press **Open Investigation**. This replaces the old row-by-row dynamic buttons and is more reliable after filtering and on mobile browsers.

### Ingestion appears stuck or empty
Open **Ingestion Center**. Run **Test Source Connection** first, then **Run Ingestion**. In `MOCK` mode, no Wazuh, Splunk or Groq service is required.

### Phone demo
Start Streamlit with:
```powershell
python -m streamlit run app.py --server.address 0.0.0.0
```
Then open `http://<LAPTOP-IP>:8501` from a phone on the same Wi-Fi. Keep Windows Firewall access enabled for the chosen private-network port.

## 25. Presentation Improvements

The dashboard uses a dark enterprise SOC theme with navy/charcoal panels, white/slate text, cyan/blue actions, fixed severity colors and a restrained AI purple accent. Charts use the same dark surface and technical typography across the application. The alert queue uses one stable selector/action instead of many dynamically created row buttons. The selector shows the first 100 filtered detections, while the queue table shows the first 60 for a stable demo layout; refine the search for a specific incident. The dedicated Ingestion Center makes source testing and loading visible rather than hiding them inside the dashboard.


## 26. Final Deliverables

The `docs/` folder contains the final technical report in DOCX/PDF and the final presentation in PPTX/PDF.

## 27. Final Demo Validation

For a clean pre-demo check (after installing the requirements), run:

```powershell
python -m unittest discover -s tests -p "test_*.py"
python scripts/final_validation.py
```

Useful Alert Queue search checks in the supplied Wazuh-shaped MOCK dataset:

- `1790411382.000997` -> one Low-severity file-integrity incident (rule 554).
- `80700` -> 125 High-severity exploitation-attempt incidents.

The current Wazuh-shaped mock contains no risk score of 9.0/10 or higher, so its Critical count is 0. The supplied Blue Team dataset contains 3 Critical records and can be used when a Critical example is needed.

For Related Events, the Investigation page documents the correlation rule: same source IP or same hostname plus same rule ID, within a 7-day window. Each related row includes the correlation reason.

MITRE mapping is source-preserving. When an event has no supplied or explicitly configured mapping, the UI reports `Not mapped from supplied telemetry.` rather than inventing a technique.

## 13. Master Enhancement Build

The current enhanced build adds a full Level-2 analyst workflow around the existing processing core:

- telemetry quality, schema version, event fingerprint and duplicate awareness
- evidence completeness and `WHY THIS ALERT FIRED` explainability
- rule version/source metadata and detection-engineering replay
- real Alert Center pagination and bounded Investigation search
- persistent case ID, priority, assignment, lifecycle and analyst decision
- timestamped case history and persistent audit events in local SQLite
- dedicated Analytics, MITRE, IOC, Reports, Audit and Settings pages
- risk × confidence matrix and MITRE tactic coverage
- raw / normalized / provenance / JSON-path inspection
- CSV, JSON and PDF reporting plus portable incident package ZIP
- safe provider/runtime diagnostics and graceful live-source failure handling
- optional AI analysis rendered as Summary / Evidence / Risk / MITRE / Limitations / Recommendations
- an explicit `AI-ASSISTED ANALYSIS // HUMAN DECISION REQUIRED` boundary

## 14. Recommended validation

Run the deterministic release validation and the full unit/integration suite from the project root:

```powershell
python -m unittest discover -s tests -p "test_*.py"
python scripts/final_validation.py
python -m compileall -q .
```

For a normal demo launch:

```powershell
python -m streamlit run app.py
```

The environment must use the project's Python 3.13 target.

See `FINAL_MASTER_ROADMAP.md` for the 120-point enhancement blueprint and implementation boundaries.


### Final UI navigation + AI behavior
- The default Streamlit automatic page navigation is disabled; the sidebar uses one grouped SOC navigation surface (Core Operations, Security Intelligence, Engineering, Governance).
- Dashboard provides Global Search, Live SOC Snapshot, Top Active Threats, SOC Health, Recent Activity and the grounded AI SOC Assistant.
- Investigation provides AI Investigation generation, evidence-grounded Incident Chat and PDF/Incident Package export.
- When `GROQ_API_KEY` is not configured, the assistant/report path falls back to deterministic answers derived from the currently loaded telemetry instead of fabricating AI output.
