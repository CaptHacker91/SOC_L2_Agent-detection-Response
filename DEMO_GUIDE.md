# Saturday Demo Guide

## Recommended environment

Use **MOCK** mode with `data/wazuh_events.jsonl`. The supplied fixture contains 1,000 records and is deterministic.

## Presentation path

1. Dashboard
2. `LAUNCH HIGH-RISK DEMO`
3. Investigation header and Evidence Completeness
4. `WHY THIS ALERT FIRED`
5. Raw / Normalized / Provenance / JSON Paths
6. Correlation Mode + relationship view
7. Human Decision Boundary
8. Mark Reviewed / Close Case
9. Optional AI Analysis
10. Download Incident PDF / Incident Package
11. Audit Console / Reports Center

## Core speaking point

> Raw Event -> Parser -> Normalizer -> Detection -> Risk/Severity/Confidence -> MITRE -> Correlation -> Investigation -> AI Assistance -> Human Decision -> Audit -> Report.

Always describe the demo source as **MOCK TELEMETRY** and AI as **ADVISORY**.


## Final 6X/AI demo flow
1. Dashboard → use Global Search or AI SOC Assistant.
2. Ask: “Which alert has the highest risk?” or “Which MITRE techniques are mapped?”
3. Open the selected incident in Investigation.
4. Use **Generate AI Investigation** for the evidence-grounded report.
5. Use **Incident Chat** for follow-up questions.
6. Record the analyst decision and export the PDF / Incident Package.

The local grounded mode works without a Groq API key; configured Groq is an optional advisory enhancement.
