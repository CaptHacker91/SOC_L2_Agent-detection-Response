# SOC L2 Agent — Final UI Build Notes

## Final presentation scope
- Hacker-terminal / SOC command-console visual language across Dashboard, Ingestion and Investigation.
- Evidence-first hierarchy: source -> parser -> normalizer -> detection -> risk/severity -> MITRE -> investigation -> AI/report.
- Dashboard threat monitor with severity KPIs, average risk/confidence, console-health indicator, interactive analytics and a demo event stream.
- Advanced Alert Center with search, severity/source/MITRE/status filters, newest-first selection and quick evidence preview.
- Telemetry Explorer with normalized contract and redacted raw-event inspection.
- Investigation console with risk/confidence bars, normalized metadata, IOC snapshot, MITRE context, workflow timeline, related-event correlation, recommendations, analyst decision, session-local notes/audit log, optional AI assistance, incident chat and PDF export.
- Ingestion Control Room with source health, diagnostics, source-safe failure handling, pipeline visualisation and normalized preview.
- Presentation Mode condenses the Dashboard for the college demonstration without disabling the core workflow.

## Integrity boundaries
- Existing detection/ingestion/normalization/risk/MITRE/reporting modules are preserved.
- No fabricated telemetry or fake provider connection state is introduced.
- AI remains advisory; analyst confirmation remains a separate step.
- Streamlit page-link icons use valid single-character emoji values.
- UI uses native Streamlit containers for structural layout instead of wrapping Streamlit widgets inside manual HTML containers.
