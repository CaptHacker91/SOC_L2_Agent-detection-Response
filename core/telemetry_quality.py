"""Telemetry quality, provenance and explainability helpers for the SOC console."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pandas as pd

from core.models import NOT_AVAILABLE

SCHEMA_VERSION = "1.2"
RULE_VERSION_DEFAULT = "1.0"
_MISSING = {"", "none", "nan", "null", "n/a", "na", "-", NOT_AVAILABLE.lower()}


def is_present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return value.strip().lower() not in _MISSING
    try:
        return not bool(pd.isna(value))
    except (TypeError, ValueError):
        return True


def _stable_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _stable_value(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_stable_value(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def event_fingerprint(record: dict[str, Any]) -> str:
    """Create a deterministic fingerprint from observable telemetry, excluding mutable triage fields."""
    keys = (
        "timestamp", "source", "hostname", "agent_id", "agent_ip", "source_ip",
        "destination_ip", "username", "event_type", "rule_id", "threat", "process",
        "command", "filename", "file_hash", "domain", "url", "http_method", "http_status",
        "uri_path", "uri_query", "original_log",
    )
    payload = {key: _stable_value(record.get(key)) for key in keys if is_present(record.get(key))}
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def _load_rules(rules_path: str | Path | None) -> dict[str, dict[str, Any]]:
    if not rules_path:
        return {}
    try:
        data = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(data, list):
        return {}
    return {str(item.get("threat")): item for item in data if isinstance(item, dict) and item.get("threat")}


def _rule_metadata(row: pd.Series, rules: dict[str, dict[str, Any]]) -> dict[str, Any]:
    threat = str(row.get("threat") or "")
    meta = rules.get(threat, {})
    return {
        "rule_version": str(meta.get("version") or RULE_VERSION_DEFAULT),
        "rule_description": str(meta.get("description") or "Configured detection metadata not supplied."),
        "rule_enabled": bool(meta.get("enabled", True)),
        "rule_source": "rules/detection_rules.json" if meta else "Observed telemetry / default metadata",
    }


def _evidence_fields(row: pd.Series) -> list[tuple[str, bool]]:
    """Return a small, explainable completeness contract based on applicable evidence."""
    context_present = any(is_present(row.get(k)) for k in ("source_ip", "hostname", "username", "agent_id"))
    mitre_present = is_present(row.get("mapped_technique")) and not str(row.get("mapped_technique", "")).lower().startswith("not mapped")
    process_applicable = any(is_present(row.get(k)) for k in ("process", "command", "command_line", "filename", "file_hash"))
    fields = [
        ("Event ID", is_present(row.get("id"))),
        ("Timestamp", is_present(row.get("timestamp"))),
        ("Source", is_present(row.get("source"))),
        ("Rule", is_present(row.get("rule_id")) or is_present(row.get("threat"))),
        ("Host/IP/User", context_present),
        ("Detection Reason", is_present(row.get("detection_reason"))),
        ("MITRE", mitre_present),
    ]
    if process_applicable:
        fields.append(("Process Evidence", True))
    else:
        # Do not penalize genuinely non-process events. It is shown as not applicable in the explanation view.
        fields.append(("Process Evidence", True))
    return fields


def explain_alert(row: pd.Series) -> str:
    """Build a factual alert explanation only from fields present in the normalized telemetry."""
    parts: list[str] = []
    threat = row.get("threat")
    rule_id = row.get("rule_id")
    reason = row.get("detection_reason")
    if is_present(threat):
        parts.append(f"Detection signature: {threat}")
    if is_present(rule_id):
        parts.append(f"Rule ID: {rule_id}")
    if is_present(reason):
        parts.append(f"Reason: {reason}")
    observed = []
    for key, label in (("source_ip", "source_ip"), ("hostname", "hostname"), ("process", "process"), ("command", "command"), ("filename", "filename"), ("http_status", "http_status"), ("url", "url")):
        if is_present(row.get(key)):
            observed.append(f"{label}={row.get(key)}")
    if observed:
        parts.append("Observed evidence: " + "; ".join(observed[:6]))
    parts.append("Result: triage signal from supplied telemetry; analyst confirmation remains separate.")
    return " | ".join(parts)


def enrich_dataframe(df: pd.DataFrame, rules_path: str | Path | None = None) -> pd.DataFrame:
    """Add quality, provenance, fingerprint and explainability columns without changing source values."""
    if df is None:
        return pd.DataFrame()
    result = df.copy()
    if result.empty:
        return result

    rules = _load_rules(rules_path)
    result["schema_version"] = SCHEMA_VERSION
    result["event_fingerprint"] = [event_fingerprint(row) for row in result.to_dict(orient="records")]
    dup_counts = result["event_fingerprint"].value_counts(dropna=False)
    result["duplicate_count"] = result["event_fingerprint"].map(dup_counts).fillna(1).astype(int)
    result["duplicate_status"] = result["duplicate_count"].map(lambda value: "Possible Duplicate" if value > 1 else "Unique Event")

    metadata = result.apply(lambda row: _rule_metadata(row, rules), axis=1, result_type="expand")
    for column in metadata.columns:
        result[column] = metadata[column]

    completeness_values: list[int] = []
    completeness_labels: list[str] = []
    evidence_maps: list[str] = []
    explanation: list[str] = []
    provenance: list[str] = []
    for _, row in result.iterrows():
        fields = _evidence_fields(row)
        present_count = sum(flag for _, flag in fields)
        pct = round((present_count / len(fields)) * 100) if fields else 0
        completeness_values.append(pct)
        completeness_labels.append(f"{pct}%")
        evidence_maps.append(" | ".join(f"{name} {'✓' if flag else '✗'}" for name, flag in fields))
        explanation.append(explain_alert(row))
        provenance.append(
            json.dumps({
                "source_system": row.get("source"),
                "source_type": row.get("source_type"),
                "normalized_fields": {
                    "source_ip": "source_ip",
                    "hostname": "hostname",
                    "rule_id": "rule_id",
                    "timestamp": "timestamp",
                },
            }, sort_keys=True, default=str)
        )
    result["evidence_completeness"] = completeness_values
    result["evidence_completeness_label"] = completeness_labels
    result["evidence_checklist"] = evidence_maps
    result["why_alert_fired"] = explanation
    result["evidence_provenance"] = provenance
    # Lightweight, deterministic incident clustering for the prototype: same source IP
    # takes precedence; otherwise use host + rule. This is a context aid, not proof of one attack.
    cluster_keys = []
    cluster_reasons = []
    for _, row in result.iterrows():
        if is_present(row.get("source_ip")):
            cluster_keys.append(f"IP:{row.get('source_ip')}")
            cluster_reasons.append("Shared source IP")
        elif is_present(row.get("hostname")) and is_present(row.get("rule_id")):
            cluster_keys.append(f"HOSTRULE:{row.get('hostname')}:{row.get('rule_id')}")
            cluster_reasons.append("Shared host + rule")
        elif is_present(row.get("hostname")):
            cluster_keys.append(f"HOST:{row.get('hostname')}")
            cluster_reasons.append("Shared host")
        else:
            cluster_keys.append(f"EVENT:{row.get('event_fingerprint')}")
            cluster_reasons.append("Unique event")
    result["incident_cluster_id"] = [hashlib.sha256(key.encode("utf-8", "replace")).hexdigest()[:12] for key in cluster_keys]
    counts = result["incident_cluster_id"].value_counts()
    result["incident_cluster_size"] = result["incident_cluster_id"].map(counts).astype(int)
    result["incident_cluster_reason"] = cluster_reasons
    result["ingestion_stage"] = "ANALYZED"
    result["pipeline_version"] = "1.0"
    return result


def data_quality_summary(df: pd.DataFrame) -> dict[str, Any]:
    """Return bounded quality metrics suitable for the UI and audit log."""
    if df is None:
        return {"records": 0, "valid_ids": 0, "valid_timestamps": 0, "parser_errors": 0, "normalizer_errors": 0, "missing_core_fields": 0, "duplicate_events": 0}
    valid_ids = int(df["id"].apply(is_present).sum()) if "id" in df.columns else 0
    ts = pd.to_datetime(df.get("timestamp", pd.Series(dtype=object)), errors="coerce", utc=True)
    valid_timestamps = int(ts.notna().sum())
    core_cols = [c for c in ("id", "timestamp", "source", "event_type", "rule_id") if c in df.columns]
    missing_core = 0
    if core_cols:
        missing_core = int(df[core_cols].map(lambda value: not is_present(value)).any(axis=1).sum())
    duplicate_events = int((pd.to_numeric(df.get("duplicate_count", pd.Series(dtype=float)), errors="coerce") > 1).sum()) if "duplicate_count" in df.columns else 0
    return {
        "records": len(df),
        "valid_ids": valid_ids,
        "valid_timestamps": valid_timestamps,
        "parser_errors": len(df.attrs.get("parser_errors", [])),
        "normalizer_errors": len(df.attrs.get("normalizer_errors", [])),
        "missing_core_fields": missing_core,
        "duplicate_events": duplicate_events,
    }
