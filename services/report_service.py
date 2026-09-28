import re
from datetime import datetime, timezone
from fpdf import FPDF

from services.incident_context import is_present

# fpdf2 wraps text by breaking at spaces only. Real web-log fields (URL,
# URI, referer, query strings, JSESSIONIDs...) are long single tokens with
# NO spaces — e.g. "/cart.do?action=changequantity&itemId=EST-26&productId=
# DB-SG-G01&JSESSIONID=SD8SL10FF5ADFF53041" (95+ chars, one word). When a
# token like that is wider than the remaining line width, fpdf2's word-wrap
# algorithm has nowhere to break and raises
# "FPDFException: Not enough horizontal space to render a single character."
# Root cause confirmed against real web-log data: uri/uri_query/referer fields
# up to ~111 chars with zero spaces (long URLs also appear in SIEM alerts). Fix:
# insert a real space every 40 chars inside any unbroken run of 40+
# non-space characters BEFORE handing text to fpdf2, so it always has a
# break point. This changes only how long tokens wrap on the PDF page —
# it never alters the actual field value shown in the Streamlit UI.
_LONG_TOKEN = re.compile(r"\S{41,}")


def _break_long_tokens(text: str, chunk: int = 40) -> str:
    def _splitter(m):
        tok = m.group(0)
        return " ".join(tok[i:i + chunk] for i in range(0, len(tok), chunk))
    return _LONG_TOKEN.sub(_splitter, text)

NA_TEXT = "Not available in supplied telemetry"

# tactic -> (investigation, containment, remediation) step lists.
# Falls back to a generic-but-honest set when the tactic is unmapped.
_RECOMMENDATIONS = {
    "Execution": {
        "investigation": ["Review process execution logs on the affected host",
                           "Identify parent process and command-line arguments"],
        "containment": ["Isolate affected host from the network if activity is ongoing",
                         "Kill the suspicious process if still running"],
        "remediation": ["Patch or remove the vulnerable execution path",
                         "Apply application allow-listing where feasible"],
    },
    "Credential Access": {
        "investigation": ["Review authentication logs for the affected account",
                           "Check for lateral movement using the credential"],
        "containment": ["Force password reset for the affected account",
                         "Revoke active sessions/tokens for the account"],
        "remediation": ["Enable MFA on the affected account",
                         "Audit credential storage and LSASS protections"],
    },
    "Impact": {
        "investigation": ["Determine scope of affected systems/files",
                           "Identify initial access vector"],
        "containment": ["Isolate affected systems immediately",
                         "Disable network shares to prevent spread"],
        "remediation": ["Restore from known-clean backups",
                         "Patch the exploited vulnerability before restoring connectivity"],
    },
    "Command and Control": {
        "investigation": ["Review outbound connections from the affected host",
                           "Identify the destination and payload delivered"],
        "containment": ["Block the destination IP/domain at the perimeter",
                         "Isolate the affected host"],
        "remediation": ["Remove the delivered payload",
                         "Review perimeter egress filtering rules"],
    },
    "Initial Access": {
        "investigation": ["Review the full request/response for the affected endpoint",
                           "Check for repeated attempts from the same source IP"],
        "containment": ["Rate-limit or block the source IP if abuse continues",
                         "Review WAF/reverse-proxy rules for the targeted path"],
        "remediation": ["Patch the targeted application endpoint",
                         "Add input validation for the parameters involved"],
    },
}

_RECOMMENDATIONS.update({
    "Persistence": {
        "investigation": ["Review startup items, scheduled tasks/cron and services changed on the host",
                           "Identify which account and process made the change"],
        "containment": ["Disable or remove the persistence mechanism after capturing evidence",
                         "Isolate the host if unauthorized changes are confirmed"],
        "remediation": ["Restore the affected configuration from a known-good baseline",
                         "Alert on future changes to the same locations"],
    },
    "Privilege Escalation": {
        "investigation": ["Review who ran the elevated command and from where",
                           "Check for changes to group membership or sudo/admin rights"],
        "containment": ["Revoke the elevated privileges or session",
                         "Reset credentials of the account involved"],
        "remediation": ["Apply least-privilege to the affected account",
                         "Patch any local privilege-escalation vulnerability involved"],
    },
    "Defense Evasion": {
        "investigation": ["Check whether logging/security tooling was disabled or tampered with",
                           "Review activity on the host around the same time"],
        "containment": ["Re-enable security controls and isolate the host if tampering is confirmed"],
        "remediation": ["Protect security tooling against tampering",
                         "Forward logs off-host so they cannot be cleared locally"],
    },
    "Lateral Movement": {
        "investigation": ["Trace the source host and account used for the remote access",
                           "Look for the same account/IP on other hosts"],
        "containment": ["Disable the account and block the source IP/host",
                         "Isolate the systems involved"],
        "remediation": ["Restrict remote-access protocols between network segments",
                         "Rotate credentials that may have been exposed"],
    },
    "Discovery": {
        "investigation": ["Identify what was enumerated and by which account/process",
                           "Check for follow-on activity from the same source"],
        "containment": ["Monitor or block the source if activity continues"],
        "remediation": ["Reduce information exposed to unprivileged accounts"],
    },
})

_GENERIC_RECOMMENDATIONS = {
    "investigation": ["Review all available logs related to this event",
                       "Correlate with other events from the same source IP/host"],
    "containment": ["Monitor the source for repeated activity",
                     "Escalate to L3 if activity persists or escalates"],
    "remediation": ["No confirmed remediation required based on current evidence",
                     "Re-evaluate if additional corroborating evidence appears"],
}


def get_recommendations(mitre_tactic, severity):
    # A SIEM may supply several tactics ("Credential Access, Initial Access");
    # use the first one we have guidance for.
    for tactic in str(mitre_tactic or "").split(","):
        if tactic.strip() in _RECOMMENDATIONS:
            return _RECOMMENDATIONS[tactic.strip()]
    return _GENERIC_RECOMMENDATIONS


def _v(alert: dict, key: str):
    """Value if genuinely present (not None/NaN/placeholder), else NA_TEXT."""
    value = alert.get(key)
    return value if is_present(value) else NA_TEXT


def build_report_data(alert: dict, ai_summary: str = "") -> dict:
    """Single source of truth for what goes in the PDF - same object shape used by the UI."""
    rec = get_recommendations(alert.get("mitre_tactic"), alert.get("severity"))
    return {
        "incident_id": alert.get("id"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "event_time": _v(alert, "event_time"),
        "source_system": _v(alert, "source"),
        "threat": _v(alert, "threat"),
        "severity": _v(alert, "severity"),
        "risk_score": alert.get("risk_score") if is_present(alert.get("risk_score")) else NA_TEXT,
        "final_detection": _v(alert, "final_detection"),
        "detection_reason": _v(alert, "detection_reason"),
        "rule_id": _v(alert, "rule_id"),
        "rule_level": _v(alert, "rule_level"),
        "rule_groups": _v(alert, "rule_groups"),
        "mitre_technique": _v(alert, "mapped_technique"),
        "mitre_technique_name": _v(alert, "mitre_technique_name"),
        "mitre_tactic": _v(alert, "mitre_tactic"),
        "source_ip": _v(alert, "source_ip"),
        "dst_ip": _v(alert, "dst_ip"),
        "hostname": _v(alert, "hostname"),
        "username": _v(alert, "username"),
        "process": _v(alert, "process"),
        "command_line": _v(alert, "command_line"),
        "file_hash": _v(alert, "file_hash"),
        "filename": _v(alert, "filename"),
        "domain": _v(alert, "domain"),
        "url": _v(alert, "url"),
        "uri_path": _v(alert, "uri_path"),
        "http_method": _v(alert, "http_method"),
        "http_status": _v(alert, "http_status"),
        "business_impact": _v(alert, "business_impact"),
        "investigation_priority": _v(alert, "investigation_priority"),
        "investigation_steps": rec["investigation"],
        "containment_actions": rec["containment"],
        "remediation_steps": rec["remediation"],
        "ai_summary": ai_summary or "Not generated for this report.",
    }


def _sanitize(text) -> str:
    """
    fpdf2's default core fonts are Latin-1 only — strip characters they
    can't render. Then break any unbroken 40+ char token so fpdf2's
    space-only word-wrap never runs out of room (see _break_long_tokens
    docstring above — this is the actual PDF-generation crash fix).
    """
    s = str(text).encode("latin-1", "replace").decode("latin-1")
    return _break_long_tokens(s)


def generate_pdf(report_data: dict) -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _sanitize("SOC L2 Agent - Incident Investigation Report"), ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6, _sanitize(f"Generated: {report_data['generated_at']} | Incident: {report_data['incident_id']}"), ln=True, align="C")
    pdf.ln(4)

    def section(title):
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_fill_color(220, 232, 196)
        pdf.cell(0, 8, _sanitize(title), ln=True, fill=True)
        pdf.set_font("Helvetica", "", 10)

    def kv(label, value):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(45, 6, _sanitize(f"{label}:"))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 6, _sanitize(value))

    section("1. Executive Summary")
    pdf.multi_cell(0, 6, _sanitize(
        f"A {report_data['severity']}-severity security event '{report_data['threat']}' was detected. "
        f"Detection result: '{report_data['final_detection']}'. Risk score: {report_data['risk_score']}/10. "
        f"SIEM rule {report_data['rule_id']} (level {report_data['rule_level']}). "
        f"MITRE technique {report_data['mitre_technique']} ({report_data['mitre_technique_name']}) under "
        f"{report_data['mitre_tactic']} tactic. Business impact: {report_data['business_impact']}. "
        f"Priority: {report_data['investigation_priority']}."
    ))

    section("2. Incident Metadata")
    kv("Incident ID", report_data["incident_id"])
    kv("Generated", report_data["generated_at"])
    kv("Event Time", report_data["event_time"])
    kv("Source System", report_data["source_system"])
    kv("Host", report_data["hostname"])

    section("3. MITRE ATT&CK Mapping")
    kv("Technique ID", report_data["mitre_technique"])
    kv("Technique Name", report_data["mitre_technique_name"])
    kv("Tactic", report_data["mitre_tactic"])

    section("4. Detection Evidence")
    kv("Detection Reason", report_data["detection_reason"])
    kv("SIEM Rule ID / Level", f"{report_data['rule_id']} / {report_data['rule_level']}")
    kv("Rule Groups", report_data["rule_groups"])
    kv("Command Line", report_data["command_line"])
    kv("HTTP Method/Status", f"{report_data['http_method']} / {report_data['http_status']}")
    kv("URI Path", report_data["uri_path"])

    section("5. Indicators of Compromise (IOC)")
    kv("Source IP", report_data["source_ip"])
    kv("Destination IP", report_data["dst_ip"])
    kv("Hostname", report_data["hostname"])
    kv("Username", report_data["username"])
    kv("Process", report_data["process"])
    kv("Domain", report_data["domain"])
    kv("URL", report_data["url"])
    kv("Filename", report_data["filename"])
    kv("File Hash", report_data["file_hash"])

    section("6. Business Impact")
    kv("Impact Level", report_data["business_impact"])
    kv("Priority", report_data["investigation_priority"])

    section("7. SOC Analyst Recommendations")
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, _sanitize("Investigation Steps:"), ln=True)
    pdf.set_font("Helvetica", "", 10)
    for step in report_data["investigation_steps"]:
        pdf.multi_cell(0, 6, _sanitize(f"- {step}"))
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, _sanitize("Containment Actions:"), ln=True)
    pdf.set_font("Helvetica", "", 10)
    for step in report_data["containment_actions"]:
        pdf.multi_cell(0, 6, _sanitize(f"- {step}"))
    pdf.set_font("Helvetica", "B", 10)
    pdf.cell(0, 6, _sanitize("Remediation Steps:"), ln=True)
    pdf.set_font("Helvetica", "", 10)
    for step in report_data["remediation_steps"]:
        pdf.multi_cell(0, 6, _sanitize(f"- {step}"))

    section("8. SOC AI Analysis")
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(0, 5, _sanitize("Note: AI-generated content. Verify before acting."))
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(0, 5, _sanitize(report_data["ai_summary"][:8000]))

    section("9. Final Verdict")
    kv("Detection Result", report_data["final_detection"])
    kv("Severity", report_data["severity"])

    pdf.set_font("Helvetica", "I", 7)
    pdf.ln(4)
    pdf.multi_cell(0, 4, _sanitize(
        "This report was generated by SOC L2 Agent. All findings are based on available "
        "telemetry only. Do not take action solely on AI-generated content without analyst verification."
    ))

    return bytes(pdf.output())
