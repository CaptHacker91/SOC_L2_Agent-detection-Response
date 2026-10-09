"""Professional, secret-safe PDF incident report generation."""

# ============================================================
# MODULE OVERVIEW / FILE KA MAIN ROLE
# Is file ka main kaam: Incident evidence ko secret-safe professional PDF report me convert karta hai.
# Neeche ke functions/classes isi responsibility ko chhote, manageable steps me divide karte hain.
# Presentation point: sir ko samjhate waqt is file ko isi role ke according explain kiya ja sakta hai.
# ============================================================
# IMPORTS: Required libraries/modules ko yaha load kiya ja raha hai.
# In imports ka use neeche data processing, UI, API integration ya testing me hota hai.
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from io import BytesIO

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from core.security import redact_text, safe_json
from services.incident_context import is_present

NA_TEXT = "Not available in supplied telemetry"
LONG_TOKEN = re.compile(r"\S{41,}")


# FUNCTION: _break_long_tokens
# Purpose: Ye internal helper ka main kaam break long tokens se related processing ko centrally handle karna hai.
# Input: text, chunk.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _break_long_tokens(text: str, chunk: int = 18) -> str:
    """Insert visual line-break opportunities into very long URLs/hashes/commands."""
    return LONG_TOKEN.sub(lambda m: " ".join(m.group(0)[i:i + chunk] for i in range(0, len(m.group(0)), chunk)), text)


_RECOMMENDATIONS = {
    "Execution": {
        "investigation": ["Review process execution logs on the affected host.", "Identify the parent process and command-line arguments."],
        "containment": ["Isolate the host if activity is ongoing.", "Stop the suspicious process only after evidence is captured."],
        "remediation": ["Patch or remove the vulnerable execution path.", "Apply application allow-listing where feasible."],
    },
    "Credential Access": {
        "investigation": ["Review authentication and credential-access logs.", "Check for the same account on other hosts."],
        "containment": ["Reset the affected account if unauthorized use is confirmed.", "Revoke active sessions/tokens where appropriate."],
        "remediation": ["Enable MFA where feasible.", "Review credential protections on the affected host."],
    },
    "Impact": {
        "investigation": ["Determine the scope of affected systems/files.", "Identify the initiating event or access path."],
        "containment": ["Isolate affected systems when destructive activity is confirmed.", "Restrict relevant network shares if evidence supports propagation risk."],
        "remediation": ["Restore from known-good backups when necessary.", "Patch the underlying weakness before normal connectivity is restored."],
    },
    "Command and Control": {
        "investigation": ["Review outbound connections from the affected host.", "Identify the exact destination and payload evidence."],
        "containment": ["Block the destination only when supported by telemetry.", "Isolate the host if active malicious communication is established."],
        "remediation": ["Remove confirmed malicious payloads.", "Review egress filtering and monitoring."],
    },
    "Initial Access": {
        "investigation": ["Review the complete request and response for the affected endpoint.", "Check for repeated activity from the same source."],
        "containment": ["Rate-limit or block the source if abuse continues and evidence supports it.", "Review WAF/reverse-proxy rules for the targeted path."],
        "remediation": ["Patch the targeted application weakness.", "Add input validation for the parameters involved."],
    },
    "Persistence": {
        "investigation": ["Review startup items, scheduled tasks/cron and services changed.", "Identify the account and process that made the change."],
        "containment": ["Disable the persistence mechanism after evidence is captured.", "Isolate the host if unauthorized persistence is confirmed."],
        "remediation": ["Restore the affected configuration from a known-good baseline.", "Monitor future changes to the same locations."],
    },
    "Privilege Escalation": {
        "investigation": ["Review who ran the elevated command and from where.", "Check for group membership or privilege changes."],
        "containment": ["Revoke unauthorized privilege or session.", "Reset credentials when evidence indicates exposure."],
        "remediation": ["Apply least privilege.", "Patch the local weakness involved if confirmed."],
    },
    "Defense Evasion": {
        "investigation": ["Check whether logging/security tooling was disabled or tampered with.", "Review activity on the host around the event time."],
        "containment": ["Re-enable security controls after capturing evidence.", "Isolate the host if tampering is confirmed."],
        "remediation": ["Protect security tooling against tampering.", "Forward logs off-host where feasible."],
    },
    "Lateral Movement": {
        "investigation": ["Trace the source host and account used for remote access.", "Look for the same account/IP on other hosts."],
        "containment": ["Disable the account or block the source when supported by evidence.", "Isolate affected systems if lateral movement is established."],
        "remediation": ["Restrict remote-access protocols between network segments.", "Rotate exposed credentials when evidence supports exposure."],
    },
}

_GENERIC_RECOMMENDATIONS = {
    "investigation": ["Review all available logs related to this event.", "Correlate the source IP/host with related telemetry."],
    "containment": ["Monitor the source for repeated activity.", "Escalate to L3 if activity persists or additional evidence appears."],
    "remediation": ["No specific remediation is established from the current telemetry.", "Re-evaluate after additional corroborating evidence is collected."],
}


# FUNCTION: get_recommendations
# Purpose: Ye function get recommendations operation handle karta hai.
# Input: mitre_tactic, severity.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def get_recommendations(mitre_tactic, severity=None):
    """Return conservative analyst guidance; recommendations are not proof of compromise."""
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for tactic in str(mitre_tactic or "").split(","):
        # Yaha condition check karke decide kiya ja raha hai ki agla logic execute karna hai ya nahi.
        if tactic.strip() in _RECOMMENDATIONS:
            return _RECOMMENDATIONS[tactic.strip()]
    return _GENERIC_RECOMMENDATIONS


# FUNCTION: _v
# Purpose: Ye internal helper ka main kaam v se related processing ko centrally handle karna hai.
# Input: alert, key.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _v(alert: dict, key: str):
    value = alert.get(key)
    return value if is_present(value) else NA_TEXT


# FUNCTION: build_report_data
# Purpose: Ye function build report data operation handle karta hai.
# Input: alert, ai_summary.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def build_report_data(alert: dict, ai_summary: str = "", related=None, case: dict | None = None, analyst_decision: str = "", analyst_note: str = "", assigned_analyst: str = "") -> dict:
    """Build a stable report payload from one incident dictionary."""
    rec = get_recommendations(alert.get("mitre_tactic"), alert.get("severity"))
    case = case or {}
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload = {
        "incident_id": _v(alert, "id"),
        "case_id": _v(case, "case_id") if case else "Not assigned",
        "source": _v(alert, "source"),
        "severity": _v(alert, "severity"),
        "rule_id": _v(alert, "rule_id"),
        "mapped_technique": _v(alert, "mapped_technique"),
        "evidence_fingerprint": _v(alert, "event_fingerprint"),
    }
    evidence_payload_hash = hashlib.sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()
    return {
        "report_version": "1.1",
        "incident_id": _v(alert, "id"),
        "case_id": _v(case, "case_id") if case else "Not assigned",
        "case_status": _v(case, "status") if case else "NEW",
        "case_priority": _v(case, "priority") if case else "P3",
        "assigned_analyst": assigned_analyst or _v(case, "assigned_analyst") if case else (assigned_analyst or "Unassigned"),
        "analyst_decision": analyst_decision or _v(case, "decision") if case else (analyst_decision or "Not recorded"),
        "analyst_note": analyst_note or _v(case, "note") if case else (analyst_note or "Not recorded"),
        "generated_at": generated_at,
        "evidence_payload_hash": evidence_payload_hash,
        "event_time": _v(alert, "timestamp"),
        "source_system": _v(alert, "source"),
        "source_type": _v(alert, "source_type"),
        "threat": _v(alert, "threat"),
        "severity": _v(alert, "severity"),
        "risk_score": _v(alert, "risk_score"),
        "confidence": _v(alert, "confidence_level"),
        "confidence_score": _v(alert, "confidence_score"),
        "confidence_reason": _v(alert, "confidence_reason"),
        "confirmation_status": _v(alert, "confirmation_status"),
        "final_detection": _v(alert, "final_detection"),
        "detection_reason": _v(alert, "detection_reason"),
        "rule_id": _v(alert, "rule_id"),
        "rule_level": _v(alert, "rule_level"),
        "rule_groups": _v(alert, "rule_groups"),
        "mitre_technique": _v(alert, "mapped_technique"),
        "mitre_technique_name": _v(alert, "mitre_technique_name"),
        "mitre_tactic": _v(alert, "mitre_tactic"),
        "mitre_mapping_source": _v(alert, "mitre_mapping_source"),
        "source_ip": _v(alert, "source_ip"),
        "destination_ip": _v(alert, "destination_ip"),
        "hostname": _v(alert, "hostname"),
        "username": _v(alert, "username"),
        "agent_id": _v(alert, "agent_id"),
        "agent_ip": _v(alert, "agent_ip"),
        "process": _v(alert, "process"),
        "command": _v(alert, "command"),
        "file_hash": _v(alert, "file_hash"),
        "filename": _v(alert, "filename"),
        "domain": _v(alert, "domain"),
        "url": _v(alert, "url"),
        "uri_path": _v(alert, "uri_path"),
        "uri_query": _v(alert, "uri_query"),
        "http_method": _v(alert, "http_method"),
        "http_status": _v(alert, "http_status"),
        "business_impact": _v(alert, "business_impact"),
        "investigation_priority": _v(alert, "investigation_priority"),
        "event_fingerprint": _v(alert, "event_fingerprint"),
        "duplicate_status": _v(alert, "duplicate_status"),
        "evidence_completeness": _v(alert, "evidence_completeness_label"),
        "evidence_checklist": _v(alert, "evidence_checklist"),
        "why_alert_fired": _v(alert, "why_alert_fired"),
        "rule_version": _v(alert, "rule_version"),
        "rule_description": _v(alert, "rule_description"),
        "rule_source": _v(alert, "rule_source"),
        "investigation_steps": rec["investigation"],
        "containment_actions": rec["containment"],
        "remediation_steps": rec["remediation"],
        "ai_summary": ai_summary or "Not generated for this report.",
        "related_events": list(related or [])[:10],
        "raw_event": safe_json(alert.get("raw_event"), max_chars=8000),
    }


# FUNCTION: _sanitize
# Purpose: Ye internal helper sanitize operation handle karta hai.
# Input: value.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def _sanitize(value) -> str:
    """Make arbitrary telemetry safe for fpdf2 core fonts and layout."""
    text = redact_text(value)
    # fpdf2 built-in Helvetica is Latin-1 based. Replace unsupported glyphs rather than crashing.
    text = text.encode("latin-1", "replace").decode("latin-1")
    return _break_long_tokens(text)


# CLASS: _SOCReportPDF
# Role: Ye internal helper ka main kaam SOCReport PDF se related processing ko centrally handle karna hai.
# Is class ke methods milkar ek focused responsibility ko handle karte hain.
class _SOCReportPDF(FPDF):
    """PDF with a consistent footer and page numbering."""

    # FUNCTION: footer
    # Purpose: Ye function ka main kaam footer se related processing ko centrally handle karna hai.
    # Input: Koi direct input parameter nahi; object/state ya module-level configuration use ho sakti hai..
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "I", 7)
        self.cell(0, 5, _sanitize(f"SOC L2 Agent | Page {self.page_no()}"), align="C")


# FUNCTION: generate_pdf
# Purpose: Ye function generate pdf operation handle karta hai.
# Input: report_data.
# Output: Caller ko required value, status, processed data ya structured result return karta hai.
# Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
def generate_pdf(report_data: dict) -> bytes:
    """Generate a multi-page secret-safe PDF report."""
    pdf = _SOCReportPDF()
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # FUNCTION: section
    # Purpose: Ye function ka main kaam section se related processing ko centrally handle karna hai.
    # Input: title.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def section(title: str):
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(225, 234, 208)
        pdf.cell(0, 8, _sanitize(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(1)

    # FUNCTION: kv
    # Purpose: Ye function ka main kaam kv se related processing ko centrally handle karna hai.
    # Input: label, value.
    # Output: Caller ko required value, status, processed data ya structured result return karta hai.
    # Motive: Is processing ko separate rakhne ka goal code ko modular, readable aur easy-to-test banana hai.
    def kv(label: str, value):
        """Render a stable two-column key/value row and always reset to the left margin."""
        label_w = 48
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(label_w, 6, _sanitize(f"{label}:"), new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _sanitize(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SOC L2 Agent - Incident Investigation Report", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, _sanitize(f"Generated: {report_data['generated_at']} | Incident: {report_data['incident_id']}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT, align="C")
    pdf.ln(4)

    section("1. Assessment Summary")
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 6, _sanitize(
        f"Detection: {report_data['final_detection']} | Severity: {report_data['severity']} | "
        f"Risk: {report_data['risk_score']}/10 | Confidence: {report_data['confidence']} | "
        f"Confirmation status: {report_data['confirmation_status']}. "
        "Severity and risk indicate triage importance; they do not by themselves confirm compromise."
    ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    section("2. Incident Metadata")
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for label, key in [
        ("Incident ID", "incident_id"), ("Event Time", "event_time"), ("Data Source", "source_system"),
        ("Source Type", "source_type"), ("Host", "hostname"), ("Agent ID", "agent_id"), ("Agent IP", "agent_ip"),
        ("Source IP", "source_ip"), ("Destination IP", "destination_ip"), ("Username", "username"),
    ]:
        kv(label, report_data[key])

    section("3. Detection Evidence")
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for label, key in [
        ("Threat / Alert", "threat"), ("Detection Reason", "detection_reason"), ("Rule ID", "rule_id"),
        ("Rule Level", "rule_level"), ("Rule Groups", "rule_groups"), ("Severity", "severity"),
        ("Risk Score", "risk_score"), ("Confidence", "confidence"), ("Confidence Score", "confidence_score"),
        ("Confidence Reason", "confidence_reason"),
    ]:
        kv(label, report_data.get(key, NA_TEXT))

    section("4. Analyst Case Control")
    for label, key in [
        ("Case ID", "case_id"), ("Case Status", "case_status"), ("Case Priority", "case_priority"),
        ("Assigned Analyst", "assigned_analyst"), ("Analyst Decision", "analyst_decision"), ("Analyst Note", "analyst_note"),
        ("Evidence Completeness", "evidence_completeness"), ("Event Fingerprint", "event_fingerprint"),
    ]:
        kv(label, report_data.get(key, NA_TEXT))

    section("5. Rule Explainability")
    for label, key in [("Why Alert Fired", "why_alert_fired"), ("Rule Version", "rule_version"), ("Rule Description", "rule_description"), ("Rule Source", "rule_source"), ("Duplicate Status", "duplicate_status"), ("Evidence Checklist", "evidence_checklist")]:
        kv(label, report_data.get(key, NA_TEXT))

    section("6. MITRE ATT&CK Mapping")
    kv("Technique ID", report_data["mitre_technique"])
    kv("Technique Name", report_data["mitre_technique_name"])
    kv("Tactic", report_data["mitre_tactic"])
    kv("Mapping Source", report_data["mitre_mapping_source"])

    section("7. Indicators and Event Fields")
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for label, key in [
        ("Process", "process"), ("Command", "command"), ("Filename", "filename"), ("File Hash", "file_hash"),
        ("Domain", "domain"), ("URL", "url"), ("URI Path", "uri_path"), ("URI Query", "uri_query"),
        ("HTTP Method", "http_method"), ("HTTP Status", "http_status"),
    ]:
        kv(label, report_data[key])

    section("8. Related Events")
    related_events = report_data.get("related_events") or []
    if related_events:
        pdf.set_font("Helvetica", "", 8)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _sanitize(
            "Correlation context: same source IP or same host + rule ID within the 7-day correlation window. "
            "Related events provide context only and do not prove compromise."
        ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for item in related_events:
            summary = (
                f"{item.get('id', NA_TEXT)} | {item.get('timestamp', NA_TEXT)} | "
                f"{item.get('severity', NA_TEXT)} | {item.get('threat', NA_TEXT)} | "
                f"{item.get('correlation', NA_TEXT)}"
            )
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 5, _sanitize(f"- {summary}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    else:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _sanitize("No related events were found using the bounded correlation rule."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    section("9. SOC Recommendations")
    # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
    for title, key in [("Investigation Steps", "investigation_steps"), ("Containment Actions", "containment_actions"), ("Remediation Steps", "remediation_steps")]:
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, _sanitize(title), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_font("Helvetica", "", 10)
        # Is loop ke through records/items ko one-by-one process kiya ja raha hai.
        for item in report_data[key]:
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(0, 6, _sanitize(f"- {item}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    section("10. AI-Assisted Analysis")
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _sanitize("AI-generated content is advisory only and must be verified against supplied telemetry."), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _sanitize(report_data["ai_summary"][:10000]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    section("11. Redacted Raw Event")
    pdf.set_font("Courier", "", 7)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 4, _sanitize(report_data["raw_event"]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.set_font("Helvetica", "I", 7)
    pdf.ln(4)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 4, _sanitize(
        "This report reflects the telemetry supplied to SOC L2 Agent. Missing values are not inferred. "
        "Do not treat severity, risk, AI output or a single rule match as independent proof of compromise."
    ), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "I", 7)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 4, _sanitize(f"Evidence payload SHA-256: {report_data.get('evidence_payload_hash', 'Not available')} | Report schema: {report_data.get('report_version', '1.0')}"), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    return bytes(pdf.output())


def build_incident_package(report_data: dict) -> bytes:
    """Build a portable incident evidence package containing report and bounded JSON artifacts."""
    pdf = generate_pdf(report_data)
    raw_event = report_data.get("raw_event") or "{}"
    normalized = {key: report_data.get(key) for key in (
        "incident_id", "case_id", "case_status", "case_priority", "assigned_analyst", "analyst_decision",
        "severity", "risk_score", "confidence", "rule_id", "rule_version", "mapped_technique", "mitre_tactic",
        "event_fingerprint", "duplicate_status", "evidence_completeness", "why_alert_fired", "source_system",
        "hostname", "source_ip", "destination_ip", "username", "timestamp",
    )}
    manifest = {
        "package_version": "1.0",
        "incident_id": report_data.get("incident_id"),
        "case_id": report_data.get("case_id"),
        "generated_at": report_data.get("generated_at"),
        "contents": ["incident_report.pdf", "evidence.json", "normalized_evidence.json", "mitre_mapping.json", "analyst_notes.txt", "case_history.json", "audit_history.json", "integrity_manifest.json"],
    }
    files = {
        "incident_report.pdf": pdf,
        "evidence.json": json.dumps({"raw_event": raw_event}, indent=2, default=str).encode("utf-8"),
        "normalized_evidence.json": json.dumps(normalized, indent=2, default=str).encode("utf-8"),
        "mitre_mapping.json": json.dumps({"technique": report_data.get("mitre_technique"), "name": report_data.get("mitre_technique_name"), "tactic": report_data.get("mitre_tactic"), "mapping_source": report_data.get("mitre_mapping_source")}, indent=2, default=str).encode("utf-8"),
        "analyst_notes.txt": _sanitize(report_data.get("analyst_note", "Not recorded")).encode("utf-8", "replace"),
        "case_history.json": json.dumps(report_data.get("case_history", []), indent=2, default=str).encode("utf-8"),
        "audit_history.json": json.dumps(report_data.get("audit_history", []), indent=2, default=str).encode("utf-8"),
    }
    for name, content in files.items():
        manifest.setdefault("sha256", {})[name] = hashlib.sha256(content).hexdigest()
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    files["integrity_manifest.json"] = manifest_bytes
    out = BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return out.getvalue()
