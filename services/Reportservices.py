"""
Report Service - PDF + HTML incident report generator.
Modular: add new report formats without touching Investigation.py.
"""
from datetime import datetime
from fpdf import FPDF


# ── Helpers ────────────────────────────────────────────────────────────────────
def _na(val):
    """Return value or 'Not available in supplied telemetry'."""
    if val in (None, "", "-", "N/A"):
        return "Not available in supplied telemetry"
    return str(val)


def build_report_data(alert: dict) -> dict:
    """Extract all available fields from alert into clean report dict."""
    return {
        "incident_id":    f"INC-{str(alert.get('id','000')).zfill(4)}",
        "timestamp":      datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "threat":         _na(alert.get("threat")),
        "severity":       _na(alert.get("severity")),
        "risk_score":     _na(alert.get("risk_score")),
        "detection":      _na(alert.get("final_detection")),
        "tool":           _na(alert.get("tool")),
        "rule_type":      _na(alert.get("rule_type")),
        "signature":      _na(alert.get("signature")),
        "technique":      _na(alert.get("mapped_technique")),
        "technique_name": _na(alert.get("mitre_sub_name")),
        "tactic":         _na(alert.get("mitre_tactic")),
        "context":        _na(alert.get("context")),
        "impact":         _na(alert.get("business_impact")),
        "priority":       _na(alert.get("investigation_priority")),
        # Optional forensic fields
        "source_ip":      _na(alert.get("source_ip")),
        "dest_ip":        _na(alert.get("destination_ip")),
        "hostname":       _na(alert.get("hostname")),
        "username":       _na(alert.get("username")),
        "process":        _na(alert.get("process_name")),
        "domain":         _na(alert.get("domain")),
        "url":            _na(alert.get("url")),
        "file_hash":      _na(alert.get("file_hash")),
        "filename":       _na(alert.get("filename")),
    }


# ── Recommendations by tactic ──────────────────────────────────────────────────
_RECS = {
    "Credential Access": {
        "investigation": [
            "Identify the affected endpoint and user account",
            "Review process creation events around detection time",
            "Check for credential-dumping tools (mimikatz, procdump)",
            "Determine whether credentials were successfully exfiltrated",
        ],
        "containment": [
            "Isolate the affected endpoint from the network",
            "Disable the compromised user account immediately",
            "Force password reset for all accounts on affected host",
            "Block C2 IPs/domains at firewall if identified",
        ],
        "remediation": [
            "Reset all potentially compromised credentials",
            "Enable MFA on all privileged accounts",
            "Deploy credential guard (Windows LSASS protection)",
            "Audit and tighten privileged access management",
        ],
    },
    "Execution": {
        "investigation": [
            "Review script execution logs (PowerShell, WMI, CMD)",
            "Identify parent process and execution chain",
            "Check for encoded/obfuscated commands",
            "Determine what payload was executed and its origin",
        ],
        "containment": [
            "Isolate affected endpoint",
            "Kill malicious processes",
            "Block execution path at EDR level",
            "Preserve memory dump for forensics",
        ],
        "remediation": [
            "Apply PowerShell Constrained Language Mode",
            "Enable Script Block Logging",
            "Deploy application allowlisting (AppLocker/WDAC)",
            "Patch vulnerable applications",
        ],
    },
    "Lateral Movement": {
        "investigation": [
            "Map all systems the attacker accessed",
            "Review authentication logs for suspicious logons",
            "Check SMB/RDP/WinRM activity from affected host",
            "Identify pivot points and credential reuse",
        ],
        "containment": [
            "Segment affected network zones",
            "Block lateral movement protocols at internal firewall",
            "Disable compromised accounts used for movement",
            "Reset all credentials on affected systems",
        ],
        "remediation": [
            "Implement network micro-segmentation",
            "Enforce least-privilege access model",
            "Deploy privileged access workstations (PAWs)",
            "Enable enhanced audit logging on all servers",
        ],
    },
    "Impact": {
        "investigation": [
            "Identify scope of data encrypted/deleted/disrupted",
            "Check for lateral spread to other systems",
            "Locate original infection vector",
            "Determine if backups are intact and unaffected",
        ],
        "containment": [
            "Isolate ALL affected systems immediately",
            "Disconnect from network to prevent further spread",
            "Preserve forensic evidence before remediation",
            "Engage incident response team",
        ],
        "remediation": [
            "Restore from verified clean backups",
            "Rebuild affected systems from golden image",
            "Patch vulnerability used for initial access",
            "Conduct full threat hunt across environment",
        ],
    },
    "Command and Control": {
        "investigation": [
            "Identify all C2 communication endpoints (IPs, domains)",
            "Review DNS query logs for beaconing patterns",
            "Check process responsible for C2 traffic",
            "Determine dwell time (how long C2 active)",
        ],
        "containment": [
            "Block C2 IPs and domains at perimeter firewall",
            "Isolate affected host",
            "Kill C2 process on endpoint",
            "Sinkhole malicious domains if possible",
        ],
        "remediation": [
            "Perform full threat hunt for similar implants",
            "Review and tighten egress filtering rules",
            "Deploy DNS security (RPZ/DNS filtering)",
            "Update threat intelligence feeds",
        ],
    },
    "Initial Access": {
        "investigation": [
            "Identify the entry vector (phishing, exploit, credentials)",
            "Review email gateway logs if phishing suspected",
            "Check vulnerable services exposed to internet",
            "Determine what was accessed post-compromise",
        ],
        "containment": [
            "Block identified malicious sender/IP/domain",
            "Patch exploited vulnerability immediately",
            "Reset credentials if valid accounts were used",
            "Enable enhanced monitoring on entry points",
        ],
        "remediation": [
            "Patch all internet-facing systems",
            "Deploy email security gateway",
            "Implement MFA on all external-facing systems",
            "Conduct security awareness training",
        ],
    },
    "Defense Evasion": {
        "investigation": [
            "Identify what security controls were bypassed",
            "Check for log clearing or tampering events",
            "Review process injection and hollowing indicators",
            "Determine what attacker was trying to hide",
        ],
        "containment": [
            "Isolate affected endpoint",
            "Restore tampered logs from SIEM backup",
            "Kill identified evasion processes",
            "Enable additional monitoring for bypass techniques",
        ],
        "remediation": [
            "Enable tamper-protected audit logging",
            "Deploy EDR with process injection detection",
            "Implement log forwarding to immutable SIEM",
            "Review and harden security tool configurations",
        ],
    },
    "Discovery": {
        "investigation": [
            "Identify what reconnaissance was performed",
            "Review which systems/accounts were queried",
            "Determine if discovery led to further attack stages",
            "Check for automated scanning tools",
        ],
        "containment": [
            "Isolate affected endpoint if active threat confirmed",
            "Block suspicious scanning activity at network level",
            "Review access rights of involved accounts",
        ],
        "remediation": [
            "Implement network segmentation to limit discovery scope",
            "Deploy deception technologies (honeypots)",
            "Enable enhanced audit logging for directory queries",
        ],
    },
    "Exfiltration": {
        "investigation": [
            "Quantify volume of data exfiltrated",
            "Identify destination of exfiltrated data",
            "Determine what data categories were exposed",
            "Check compliance/regulatory notification requirements",
        ],
        "containment": [
            "Block exfiltration channels at firewall",
            "Isolate affected systems",
            "Engage legal/compliance team",
            "Preserve all network logs for investigation",
        ],
        "remediation": [
            "Deploy Data Loss Prevention (DLP) solution",
            "Implement egress filtering",
            "Classify and protect sensitive data assets",
            "Notify affected parties per regulatory requirements",
        ],
    },
}

_DEFAULT_RECS = {
    "investigation": [
        "Review all available logs related to this alert",
        "Identify affected systems and users",
        "Determine the attack timeline",
        "Assess scope and potential impact",
    ],
    "containment": [
        "Isolate affected systems if active threat confirmed",
        "Block identified malicious indicators at firewall",
        "Disable compromised accounts",
    ],
    "remediation": [
        "Patch identified vulnerabilities",
        "Restore affected systems from clean backup",
        "Enhance monitoring for similar threats",
        "Update detection rules",
    ],
}


def get_recommendations(tactic: str) -> dict:
    return _RECS.get(tactic, _DEFAULT_RECS)


# ── PDF Generator ──────────────────────────────────────────────────────────────
class SOCReportPDF(FPDF):
    """Custom FPDF subclass with SOC-styled header/footer."""

    def header(self):
        self.set_fill_color(79, 100, 40)   # olive-dark
        self.rect(0, 0, 210, 18, "F")
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(255, 255, 255)
        self.set_xy(0, 4)
        self.cell(210, 10, "SOC L2 Agent - Incident Investigation Report", align="C")
        self.set_text_color(0, 0, 0)
        self.ln(14)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 90, 60)
        self.cell(0, 6, f"SOC L2 Agent | Page {self.page_no()} | CONFIDENTIAL", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 12)
        self.set_fill_color(220, 232, 196)  # olive-light
        self.set_text_color(79, 100, 40)
        self.cell(0, 8, f"  {title}", ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv_row(self, key: str, value: str, key_w: int = 50):
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(90, 60, 20)
        x = self.get_x()
        y = self.get_y()
        self.cell(key_w, 6, f"{key}:", ln=False)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(0, 0, 0)
        val_w = self.w - self.r_margin - self.get_x()
        if val_w < 20:
            self.ln(6)
            val_w = self.w - self.r_margin - self.l_margin
        self.multi_cell(val_w, 6, str(value)[:300])

    def bullet(self, text: str):
        self.set_font("Helvetica", "", 9)
        self.set_text_color(40, 40, 40)
        self.cell(8, 6, "-", ln=False)
        self.multi_cell(self.w - self.r_margin - self.l_margin, 6, text)


def generate_pdf(alert: dict, ai_summary: str = "") -> bytes:
    """
    Generate a professional SOC incident report PDF.
    Returns bytes - use st.download_button with mime='application/pdf'.
    """
    r    = build_report_data(alert)
    recs = get_recommendations(alert.get("mitre_tactic", ""))
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    pdf = SOCReportPDF()
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    pdf.set_margins(14, 22, 14)

    # ── Title block ───────────────────────────────────────────────────────────
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(79, 100, 40)
    pdf.cell(0, 10, "INCIDENT INVESTIGATION REPORT", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 80, 40)
    pdf.cell(0, 6, f"Generated: {now}  |  Incident: {r['incident_id']}", ln=True, align="C")
    pdf.ln(4)

    # ── 1. Executive Summary ──────────────────────────────────────────────────
    pdf.section_title("1. Executive Summary")
    sev = r["severity"]
    summary = (
        f"A {sev}-severity security event '{r['threat']}' was detected by {r['tool']} "
        f"({r['rule_type']} rule). The detection engine classified this as '{r['detection']}' "
        f"with a risk score of {r['risk_score']}/10. "
        f"MITRE ATT&CK technique {r['technique']} ({r['technique_name']}) "
        f"under the {r['tactic']} tactic was identified. "
        f"Business impact is assessed as {r['impact']}. "
        f"Investigation priority: {r['priority']}."
    )
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin, 6, summary)
    pdf.ln(4)

    # ── 2. Incident Metadata ──────────────────────────────────────────────────
    pdf.section_title("2. Incident Metadata")
    for k, v in [
        ("Incident ID",     r["incident_id"]),
        ("Detection Time",  r["timestamp"]),
        ("Threat Name",     r["threat"]),
        ("Severity",        r["severity"]),
        ("Risk Score",      f"{r['risk_score']} / 10"),
        ("Detection",       r["detection"]),
        ("Detection Tool",  r["tool"]),
        ("Rule Type",       r["rule_type"]),
        ("Status",          "Under Investigation"),
        ("Priority",        r["priority"]),
    ]:
        pdf.kv_row(k, v)
    pdf.ln(4)

    # ── 3. MITRE ATT&CK ───────────────────────────────────────────────────────
    pdf.section_title("3. MITRE ATT&CK Mapping")
    for k, v in [
        ("Technique ID",    r["technique"]),
        ("Technique Name",  r["technique_name"]),
        ("Tactic",          r["tactic"]),
        ("Context",         r["context"]),
    ]:
        pdf.kv_row(k, v)
    pdf.ln(4)

    # ── 4. Detection Evidence ─────────────────────────────────────────────────
    pdf.section_title("4. Detection Evidence")
    pdf.kv_row("Signature", r["signature"])
    pdf.ln(2)

    # ── 5. IOC / Forensic Fields ──────────────────────────────────────────────
    pdf.section_title("5. Indicators of Compromise (IOC)")
    ioc_fields = [
        ("Source IP",    r["source_ip"]),
        ("Destination IP", r["dest_ip"]),
        ("Hostname",     r["hostname"]),
        ("Username",     r["username"]),
        ("Process",      r["process"]),
        ("Domain",       r["domain"]),
        ("URL",          r["url"]),
        ("File Hash",    r["file_hash"]),
        ("Filename",     r["filename"]),
    ]
    for k, v in ioc_fields:
        pdf.kv_row(k, v)
    pdf.ln(4)

    # ── 6. Business Impact ────────────────────────────────────────────────────
    pdf.section_title("6. Business Impact")
    pdf.kv_row("Impact Level",    r["impact"])
    impact_desc = {
        "Very High": (
            "Critical threat to business operations. Potential for data breach, "
            "system compromise, financial loss, or regulatory violation. "
            "Immediate executive escalation required."
        ),
        "High": (
            "Significant security risk. Potential for unauthorized access to "
            "sensitive data or systems. Priority investigation and containment required."
        ),
        "Moderate": (
            "Suspicious activity with potential business impact if not addressed. "
            "Investigation required to determine actual impact."
        ),
        "Low": (
            "Low-confidence or low-impact suspicious activity. "
            "Monitor and investigate when capacity allows."
        ),
    }.get(r["impact"], "Impact assessment based on available telemetry.")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin, 6, impact_desc)
    pdf.ln(4)

    # ── 7. SOC Recommendations ────────────────────────────────────────────────
    pdf.section_title("7. SOC Analyst Recommendations")

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(79, 100, 40)
    pdf.cell(0, 7, "  Investigation Steps:", ln=True)
    pdf.set_text_color(0, 0, 0)
    for step in recs["investigation"]:
        pdf.bullet(step)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(139, 0, 0)
    pdf.cell(0, 7, "  Containment Actions:", ln=True)
    pdf.set_text_color(0, 0, 0)
    for step in recs["containment"]:
        pdf.bullet(step)
    pdf.ln(2)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(0, 80, 0)
    pdf.cell(0, 7, "  Remediation Steps:", ln=True)
    pdf.set_text_color(0, 0, 0)
    for step in recs["remediation"]:
        pdf.bullet(step)
    pdf.ln(4)

    # ── 8. AI SOC Analysis (optional) ────────────────────────────────────────
    if ai_summary and ai_summary.strip():
        pdf.section_title("8. SOC AI Analysis")
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 80, 40)
        pdf.cell(0, 5, "Note: AI-generated content. Verify against telemetry before acting.", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        # Sanitize for PDF (remove markdown bold)
        clean = ai_summary.replace("**", "").replace("*", "").replace("#", "")
        pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin, 6, clean[:3000])  # cap length
        pdf.ln(4)

    # ── 9. Final Verdict ──────────────────────────────────────────────────────
    pdf.section_title("9. Final Verdict")
    pdf.kv_row("Detection Result", r["detection"])
    pdf.kv_row("Severity",         r["severity"])
    pdf.kv_row("Risk Score",       f"{r['risk_score']} / 10")
    pdf.kv_row("Analyst Action",   "Investigate per priority level and SOC playbook")
    pdf.kv_row("Report Generated", now)
    pdf.ln(4)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 90, 60)
    pdf.multi_cell(pdf.w - pdf.r_margin - pdf.l_margin, 5,
        "This report was generated by SOC L2 Agent. All findings are based on "
        "available telemetry only. Do not take action solely on AI-generated content "
        "without analyst verification."
    )

    return bytes(pdf.output())