from datetime import datetime, timezone
from fpdf import FPDF

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

_GENERIC_RECOMMENDATIONS = {
    "investigation": ["Review all available logs related to this event",
                       "Correlate with other events from the same source IP/host"],
    "containment": ["Monitor the source for repeated activity",
                     "Escalate to L3 if activity persists or escalates"],
    "remediation": ["No confirmed remediation required based on current evidence",
                     "Re-evaluate if additional corroborating evidence appears"],
}


def get_recommendations(mitre_tactic, severity):
    return _RECOMMENDATIONS.get(mitre_tactic, _GENERIC_RECOMMENDATIONS)


def build_report_data(alert: dict, ai_summary: str = "") -> dict:
    """Single source of truth for what goes in the PDF — same object shape used by the UI."""
    rec = get_recommendations(alert.get("mitre_tactic"), alert.get("severity"))
    return {
        "incident_id": alert.get("id"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "threat": alert.get("threat") or NA_TEXT,
        "severity": alert.get("severity") or NA_TEXT,
        "risk_score": alert.get("risk_score"),
        "final_detection": alert.get("final_detection") or NA_TEXT,
        "detection_reason": alert.get("detection_reason") or NA_TEXT,
        "mitre_technique": alert.get("mapped_technique") or NA_TEXT,
        "mitre_technique_name": alert.get("mitre_technique_name") or NA_TEXT,
        "mitre_tactic": alert.get("mitre_tactic") or NA_TEXT,
        "source_ip": alert.get("source_ip") or NA_TEXT,
        "hostname": alert.get("hostname") or NA_TEXT,
        "username": alert.get("username") or NA_TEXT,
        "url": alert.get("url") or NA_TEXT,
        "uri_path": alert.get("uri_path") or NA_TEXT,
        "http_method": alert.get("http_method") or NA_TEXT,
        "http_status": alert.get("http_status") if alert.get("http_status") is not None else NA_TEXT,
        "business_impact": alert.get("business_impact") or NA_TEXT,
        "investigation_priority": alert.get("investigation_priority") or NA_TEXT,
        "investigation_steps": rec["investigation"],
        "containment_actions": rec["containment"],
        "remediation_steps": rec["remediation"],
        "ai_summary": ai_summary or "Not generated for this report.",
    }


def _sanitize(text) -> str:
    """fpdf2's default core fonts are Latin-1 only — strip characters they can't render."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


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
        f"MITRE technique {report_data['mitre_technique']} ({report_data['mitre_technique_name']}) under "
        f"{report_data['mitre_tactic']} tactic. Business impact: {report_data['business_impact']}. "
        f"Priority: {report_data['investigation_priority']}."
    ))

    section("2. Incident Metadata")
    kv("Incident ID", report_data["incident_id"])
    kv("Generated", report_data["generated_at"])

    section("3. MITRE ATT&CK Mapping")
    kv("Technique ID", report_data["mitre_technique"])
    kv("Technique Name", report_data["mitre_technique_name"])
    kv("Tactic", report_data["mitre_tactic"])

    section("4. Detection Evidence")
    kv("Detection Reason", report_data["detection_reason"])
    kv("HTTP Method/Status", f"{report_data['http_method']} / {report_data['http_status']}")
    kv("URI Path", report_data["uri_path"])

    section("5. Indicators of Compromise (IOC)")
    kv("Source IP", report_data["source_ip"])
    kv("Hostname", report_data["hostname"])
    kv("Username", report_data["username"])
    kv("URL", report_data["url"])

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
    pdf.multi_cell(0, 5, _sanitize(report_data["ai_summary"][:3000]))

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
