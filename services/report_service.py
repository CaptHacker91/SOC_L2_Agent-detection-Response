"""
Report Service - PDF Incident Report Generator
BUG FIX: All unicode/emoji chars stripped before writing to PDF (latin-1 safe).
Uses fpdf2 with Helvetica font (built-in, no external font file needed).
"""
import re
from datetime import datetime
from fpdf import FPDF


# ── Unicode sanitizer ──────────────────────────────────────────────────────────
def _safe(text: str, max_len: int = 400) -> str:
    """
    Strip all non-latin-1 characters (emojis, unicode symbols) so fpdf
    never raises 'latin-1 codec can't encode character' error.
    Replaces emojis with ASCII equivalents where possible.
    """
    if not text:
        return "Not available in supplied telemetry"

    replacements = {
        # Common emojis in SOC context
        "🔴": "[CRITICAL]", "🟠": "[HIGH]", "🟡": "[MEDIUM]", "🟢": "[LOW]",
        "🛡️": "[SOC]", "🛡": "[SOC]", "🔍": "[INVESTIGATE]", "⚠️": "[WARNING]",
        "⚠": "[WARNING]", "❌": "[ERROR]", "✅": "[OK]", "📋": "[LOG]",
        "🎯": "[TARGET]", "💼": "[BUSINESS]", "🤖": "[AI]", "📄": "[REPORT]",
        "⏱️": "[TIMELINE]", "⏱": "[TIMELINE]", "🚨": "[ALERT]",
        "👨\u200d💻": "[DEV]", "✦": "*", "✧": "*",
        # Common unicode punctuation
        "\u2014": "-", "\u2013": "-", "\u2022": "-",
        "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
        "\u2026": "...", "\u00b7": ".", "\u00d7": "x",
    }

    for orig, repl in replacements.items():
        text = text.replace(orig, repl)

    # Strip any remaining non-latin-1 characters
    text = text.encode("latin-1", errors="ignore").decode("latin-1")

    return text[:max_len]


def _na(val) -> str:
    if val in (None, "", "-", "N/A", "—"):
        return "Not available in supplied telemetry"
    return _safe(str(val))


# ── Recommendations by tactic ──────────────────────────────────────────────────
_RECS = {
    "Credential Access": {
        "investigation": [
            "Identify the affected endpoint and user account",
            "Review process creation events around detection time",
            "Check for credential-dumping tools (mimikatz, procdump, etc.)",
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
            "Identify parent process and full execution chain",
            "Check for encoded or obfuscated commands",
            "Determine what payload was executed and its origin",
        ],
        "containment": [
            "Isolate affected endpoint immediately",
            "Kill malicious processes identified in logs",
            "Block execution path at EDR level",
            "Preserve memory dump for forensic analysis",
        ],
        "remediation": [
            "Apply PowerShell Constrained Language Mode",
            "Enable Script Block Logging across all endpoints",
            "Deploy application allowlisting (AppLocker/WDAC)",
            "Patch vulnerable applications",
        ],
    },
    "Lateral Movement": {
        "investigation": [
            "Map all systems the attacker accessed from origin host",
            "Review authentication logs for suspicious logons",
            "Check SMB/RDP/WinRM activity from affected host",
            "Identify pivot points and credential reuse patterns",
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
            "Identify scope of data encrypted, deleted, or disrupted",
            "Check for lateral spread to additional systems",
            "Locate original infection vector",
            "Determine if backups are intact and unaffected",
        ],
        "containment": [
            "Isolate ALL affected systems immediately",
            "Disconnect from network to prevent further spread",
            "Preserve forensic evidence before remediation",
            "Engage incident response team and management",
        ],
        "remediation": [
            "Restore from verified clean backups",
            "Rebuild affected systems from golden image",
            "Patch vulnerability used for initial access",
            "Conduct full threat hunt across entire environment",
        ],
    },
    "Command and Control": {
        "investigation": [
            "Identify all C2 communication endpoints (IPs, domains)",
            "Review DNS query logs for beaconing patterns",
            "Check which process is responsible for C2 traffic",
            "Determine dwell time (how long C2 was active)",
        ],
        "containment": [
            "Block C2 IPs and domains at perimeter firewall",
            "Isolate affected host from network",
            "Kill C2 process on affected endpoint",
            "Sinkhole malicious domains if possible",
        ],
        "remediation": [
            "Perform full threat hunt for similar implants",
            "Review and tighten egress filtering rules",
            "Deploy DNS security (RPZ / DNS filtering)",
            "Update threat intelligence feeds",
        ],
    },
    "Initial Access": {
        "investigation": [
            "Identify the entry vector (phishing, exploit, valid credentials)",
            "Review email gateway logs if phishing is suspected",
            "Check vulnerable services exposed to the internet",
            "Determine what was accessed post-compromise",
        ],
        "containment": [
            "Block identified malicious sender, IP, or domain",
            "Patch exploited vulnerability immediately",
            "Reset credentials if valid accounts were abused",
            "Enable enhanced monitoring on entry points",
        ],
        "remediation": [
            "Patch all internet-facing systems",
            "Deploy email security gateway with sandboxing",
            "Implement MFA on all external-facing systems",
            "Conduct security awareness training",
        ],
    },
    "Defense Evasion": {
        "investigation": [
            "Identify what security controls were bypassed",
            "Check for log clearing or tampering events (Event ID 1102)",
            "Review process injection and hollowing indicators",
            "Determine what the attacker was attempting to conceal",
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
            "Review which systems and accounts were queried",
            "Determine if discovery led to further attack stages",
            "Check for automated scanning tools or scripts",
        ],
        "containment": [
            "Isolate affected endpoint if active threat is confirmed",
            "Block suspicious scanning activity at network level",
            "Review and restrict access rights of involved accounts",
        ],
        "remediation": [
            "Implement network segmentation to limit discovery scope",
            "Deploy deception technologies (honeypots, honey tokens)",
            "Enable enhanced audit logging for directory service queries",
        ],
    },
    "Exfiltration": {
        "investigation": [
            "Quantify the volume of data exfiltrated",
            "Identify the destination of exfiltrated data",
            "Determine which data categories were exposed",
            "Check compliance and regulatory notification requirements",
        ],
        "containment": [
            "Block exfiltration channels at perimeter firewall",
            "Isolate all affected systems immediately",
            "Engage legal and compliance team",
            "Preserve all network logs for investigation",
        ],
        "remediation": [
            "Deploy Data Loss Prevention (DLP) solution",
            "Implement strict egress filtering",
            "Classify and protect sensitive data assets",
            "Notify affected parties per applicable regulations",
        ],
    },
}

_DEFAULT_RECS = {
    "investigation": [
        "Review all available logs related to this alert",
        "Identify affected systems and users",
        "Determine the attack timeline and scope",
        "Assess potential business impact",
    ],
    "containment": [
        "Isolate affected systems if active threat is confirmed",
        "Block identified malicious indicators at firewall",
        "Disable compromised accounts as a precaution",
    ],
    "remediation": [
        "Patch identified vulnerabilities",
        "Restore affected systems from clean backup",
        "Enhance monitoring for similar future threats",
        "Update detection rules based on findings",
    ],
}


def get_recommendations(tactic: str) -> dict:
    return _RECS.get(tactic, _DEFAULT_RECS)


def build_report_data(alert: dict) -> dict:
    return {
        "incident_id":    f"INC-{str(alert.get('id', '000')).zfill(4)}",
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


# ── PDF Generator ──────────────────────────────────────────────────────────────
class SOCReportPDF(FPDF):

    def header(self):
        self.set_fill_color(79, 100, 40)
        self.rect(0, 0, 210, 16, "F")
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(255, 255, 255)
        self.set_xy(0, 3)
        self.cell(210, 10, "SOC L2 Agent - Incident Investigation Report", align="C")
        self.set_text_color(0, 0, 0)
        self.ln(13)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(120, 90, 60)
        self.cell(0, 6, f"SOC L2 Agent | Page {self.page_no()} | CONFIDENTIAL", align="C")

    def section_title(self, title: str):
        self.set_font("Helvetica", "B", 11)
        self.set_fill_color(220, 232, 196)
        self.set_text_color(79, 100, 40)
        w = self.w - self.l_margin - self.r_margin
        self.cell(w, 7, f"  {_safe(title)}", ln=True, fill=True)
        self.set_text_color(0, 0, 0)
        self.ln(2)

    def kv(self, key: str, value: str, key_w: int = 50):
        avail = self.w - self.l_margin - self.r_margin
        self.set_font("Helvetica", "B", 9)
        self.set_text_color(90, 60, 20)
        self.cell(key_w, 6, f"{_safe(key, 40)}:", ln=False)
        self.set_font("Helvetica", "", 9)
        self.set_text_color(0, 0, 0)
        self.multi_cell(avail - key_w, 6, _safe(value))

    def bullet(self, text: str):
        avail = self.w - self.l_margin - self.r_margin
        self.set_font("Helvetica", "", 9)
        self.set_text_color(40, 40, 40)
        self.cell(6, 6, "-", ln=False)
        self.multi_cell(avail - 6, 6, _safe(text))


def generate_pdf(alert: dict, ai_summary: str = "") -> bytes:
    """
    Generate PDF incident report. Returns bytes for st.download_button.
    BUG FIX: All text passes through _safe() which strips non-latin-1 chars.
    """
    r    = build_report_data(alert)
    recs = get_recommendations(alert.get("mitre_tactic", ""))
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    pdf = SOCReportPDF()
    pdf.set_auto_page_break(auto=True, margin=14)
    pdf.add_page()
    pdf.set_margins(14, 20, 14)

    # Title
    pdf.set_font("Helvetica", "B", 15)
    pdf.set_text_color(79, 100, 40)
    avail = pdf.w - pdf.l_margin - pdf.r_margin
    pdf.cell(avail, 9, "INCIDENT INVESTIGATION REPORT", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(100, 80, 40)
    pdf.cell(avail, 6, f"Generated: {now}  |  Incident: {r['incident_id']}", ln=True, align="C")
    pdf.ln(4)

    # 1. Executive Summary
    pdf.section_title("1. Executive Summary")
    summary = (
        f"A {r['severity']}-severity security event '{r['threat']}' was detected by {r['tool']} "
        f"({r['rule_type']} rule). Detection result: '{r['detection']}'. "
        f"Risk score: {r['risk_score']}/10. "
        f"MITRE technique {r['technique']} ({r['technique_name']}) under {r['tactic']} tactic. "
        f"Business impact: {r['impact']}. Priority: {r['priority']}."
    )
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(avail, 6, _safe(summary))
    pdf.ln(3)

    # 2. Incident Metadata
    pdf.section_title("2. Incident Metadata")
    for k, v in [
        ("Incident ID",    r["incident_id"]),
        ("Generated",      r["timestamp"]),
        ("Threat",         r["threat"]),
        ("Severity",       r["severity"]),
        ("Risk Score",     f"{r['risk_score']} / 10"),
        ("Detection",      r["detection"]),
        ("Detection Tool", r["tool"]),
        ("Rule Type",      r["rule_type"]),
        ("Status",         "Under Investigation"),
        ("Priority",       r["priority"]),
    ]:
        pdf.kv(k, v)
    pdf.ln(3)

    # 3. MITRE ATT&CK
    pdf.section_title("3. MITRE ATT&CK Mapping")
    for k, v in [
        ("Technique ID",   r["technique"]),
        ("Technique Name", r["technique_name"]),
        ("Tactic",         r["tactic"]),
        ("Context",        r["context"]),
    ]:
        pdf.kv(k, v)
    pdf.ln(3)

    # 4. Detection Evidence
    pdf.section_title("4. Detection Evidence")
    pdf.kv("Signature", r["signature"])
    pdf.ln(3)

    # 5. IOC
    pdf.section_title("5. Indicators of Compromise (IOC)")
    for k, v in [
        ("Source IP",      r["source_ip"]),
        ("Destination IP", r["dest_ip"]),
        ("Hostname",       r["hostname"]),
        ("Username",       r["username"]),
        ("Process",        r["process"]),
        ("Domain",         r["domain"]),
        ("URL",            r["url"]),
        ("File Hash",      r["file_hash"]),
        ("Filename",       r["filename"]),
    ]:
        pdf.kv(k, v)
    pdf.ln(3)

    # 6. Business Impact
    pdf.section_title("6. Business Impact")
    pdf.kv("Impact Level", r["impact"])
    impact_map = {
        "Very High": (
            "Critical threat to business operations. Potential for data breach, "
            "system compromise, or financial loss. Immediate executive escalation required."
        ),
        "High": (
            "Significant security risk requiring priority investigation and containment. "
            "Potential for unauthorized access to sensitive data or systems."
        ),
        "Moderate": (
            "Suspicious activity with potential business impact if unaddressed. "
            "Investigation required to determine actual impact."
        ),
        "Low": (
            "Low-confidence or low-impact activity. "
            "Monitor and investigate when capacity allows."
        ),
    }
    desc = impact_map.get(r["impact"], "Impact assessed based on available telemetry.")
    pdf.set_font("Helvetica", "", 9)
    pdf.multi_cell(avail, 6, _safe(desc))
    pdf.ln(3)

    # 7. SOC Recommendations
    pdf.section_title("7. SOC Analyst Recommendations")
    for section_label, steps in [
        ("Investigation Steps", recs["investigation"]),
        ("Containment Actions", recs["containment"]),
        ("Remediation Steps",   recs["remediation"]),
    ]:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(79, 100, 40)
        pdf.cell(avail, 6, section_label + ":", ln=True)
        pdf.set_text_color(0, 0, 0)
        for step in steps:
            pdf.bullet(step)
        pdf.ln(2)

    # 8. AI SOC Analysis
    if ai_summary and ai_summary.strip():
        pdf.section_title("8. SOC AI Analysis")
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(100, 80, 40)
        pdf.cell(avail, 5, "Note: AI-generated content. Verify before acting.", ln=True)
        pdf.set_text_color(0, 0, 0)
        pdf.set_font("Helvetica", "", 9)
        pdf.multi_cell(avail, 6, _safe(ai_summary, max_len=2000))
        pdf.ln(3)

    # 9. Final Verdict
    pdf.section_title("9. Final Verdict")
    for k, v in [
        ("Detection Result", r["detection"]),
        ("Severity",         r["severity"]),
        ("Risk Score",       f"{r['risk_score']} / 10"),
        ("Analyst Action",   "Investigate per priority and SOC playbook"),
        ("Report Time",      now),
    ]:
        pdf.kv(k, v)
    pdf.ln(3)

    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(120, 90, 60)
    pdf.multi_cell(avail, 5,
        "This report was generated by SOC L2 Agent. All findings are based on "
        "available telemetry only. Do not take action solely on AI-generated content "
        "without analyst verification."
    )

    return bytes(pdf.output())