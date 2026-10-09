# SOC L2 Agent — Architecture

## Core flow

`MOCK / WAZUH / SPLUNK -> Parser -> Normalizer -> Data Quality -> Detection -> Risk/Severity/Confidence -> Correlation -> MITRE -> Investigation -> AI Assistance -> Human Decision -> Case Store -> Audit -> Report / Incident Package`

## Design boundaries

- **Telemetry is authoritative.** AI output is advisory only.
- **Detection is not confirmation.** Severity and risk describe triage importance.
- **Missing evidence stays missing.** No external threat facts are invented by the core pipeline.
- **Live-source failure is graceful.** A previously verified dataset can remain visible when a provider is unavailable.
- **Analyst state is persistent.** Case status, assignment, decision and audit history are stored locally in SQLite.
- **Exports are redaction-safe.** Reports and incident packages are generated from sanitized evidence.

## Processing contract

The normalized event contract provides stable downstream fields. Additional quality fields are appended without replacing source fields:

- `schema_version`
- `event_fingerprint`
- `duplicate_count` / `duplicate_status`
- `rule_version` / `rule_description` / `rule_enabled`
- `evidence_completeness`
- `evidence_checklist`
- `why_alert_fired`
- `evidence_provenance`

## Source adapters

`core/data_source.py` selects the configured provider. MOCK uses the supplied Wazuh-shaped JSONL fixture; Wazuh and Splunk are optional live adapters. All sources converge into the same parser/normalizer/analysis contract.

## Persistence

`services/case_store.py` uses SQLite in `.soc_state/soc_cases.db`. The state is intentionally local to the prototype and is not positioned as an enterprise SIEM audit replacement.

## AI boundary

AI services receive bounded incident context. The application presents structured AI sections and always keeps an explicit **HUMAN DECISION REQUIRED** boundary.
