class AlertTriangle:
    """
    Alert Triangle Engine
    Adds context, business impact, investigation priority,
    and ATT&CK sub-technique name to every alert.
    """

    def generate(self, dataframe):
        dataframe["context"]                = dataframe["mapped_technique"].apply(self._context)
        dataframe["business_impact"]        = dataframe["severity"].apply(self._impact)
        dataframe["investigation_priority"] = dataframe.apply(self._priority, axis=1)
        return dataframe

    def _context(self, technique):
        ctx = {
            # Execution
            "T1059":       "Command interpreter abuse",
            "T1059.001":   "PowerShell Execution",
            "T1059.005":   "VBScript/VBA Execution",
            "T1059.006":   "Python Script Execution",
            "T1059.007":   "JavaScript Execution",
            "T1059.008":   "Network CLI Abuse",
            "T1047":       "WMI Execution",
            "T1204.001":   "Malicious Link Click",
            "T1204.002":   "Malicious File Execution",
            # Persistence
            "T1547.001":   "Registry Run Key Persistence",
            "T1053.005":   "Scheduled Task Persistence",
            "T1543.003":   "Malicious Windows Service",
            "T1546.003":   "WMI Event Subscription",
            "T1546.012":   "IFEO Hijacking",
            "T1505.003":   "Web Shell Deployed",
            "T1505.004":   "IIS Component Persistence",
            "T1574.002":   "DLL Side-Loading",
            "T1176":       "Malicious Browser Extension",
            # Privilege Escalation
            "T1068":       "Kernel/Service Exploitation",
            "T1134.001":   "Token Impersonation",
            "T1548.005":   "Cloud Role Escalation",
            "T1611":       "Container Escape",
            # Defense Evasion
            "T1055":       "Process Injection",
            "T1055.001":   "DLL Injection",
            "T1055.012":   "Process Hollowing",
            "T1027":       "Payload Obfuscation",
            "T1027.002":   "Packed Binary",
            "T1070.004":   "Evidence Tampering",
            "T1218.010":   "Regsvr32 LOLBin",
            "T1218.005":   "Mshta LOLBin",
            "T1218.004":   "InstallUtil LOLBin",
            "T1218":       "Signed Binary Abuse",
            "T1562.008":   "CloudTrail Disabled",
            "T1553.002":   "Rogue Code Signing",
            "T1564.001":   "Hidden File",
            "T1564.004":   "ADS Abuse",
            "T1014":       "Rootkit Active",
            "T1090.003":   "Tor Proxy",
            "T1610":       "Malicious Container",
            "T1484.001":   "Group Policy Tampered",
            "T1484.002":   "Domain Policy Modified",
            # Credential Access
            "T1003":       "Credential Dumping",
            "T1003.001":   "LSASS Dump",
            "T1003.002":   "SAM Dump",
            "T1110":       "Brute Force Attack",
            "T1110.004":   "Credential Stuffing",
            "T1056.001":   "Keylogger Running",
            "T1056.002":   "Screen Capture Input",
            "T1552.005":   "Cloud Metadata API Abuse",
            "T1552.007":   "Container Credential Theft",
            "T1558.001":   "Golden Ticket Attack",
            "T1558.002":   "Silver Ticket Attack",
            "T1550.002":   "Pass-the-Hash",
            "T1550.003":   "Pass-the-Ticket",
            "T1550.004":   "Session Hijacking",
            "T1550.001":   "App Token Abuse",
            # Discovery
            "T1082":       "System Reconnaissance",
            "T1083":       "File System Enumeration",
            "T1033":       "User Discovery",
            "T1049":       "Network Connection Discovery",
            "T1046":       "Port Scanning",
            "T1018":       "Remote Host Discovery",
            "T1057":       "Process Enumeration",
            "T1007":       "Service Discovery",
            "T1012":       "Registry Query",
            "T1016":       "Network Config Discovery",
            "T1016.001":   "Internet Connectivity Check",
            "T1040":       "Network Sniffing",
            "T1135":       "SMB Share Enumeration",
            "T1069.001":   "Local Group Enumeration",
            "T1069.002":   "Domain Group Enumeration",
            "T1087.001":   "Local User Enumeration",
            "T1087.004":   "Cloud User Enumeration",
            "T1518.001":   "AV/EDR Discovery",
            "T1526":       "Cloud Service Discovery",
            "T1613":       "K8s Resource Discovery",
            # Lateral Movement
            "T1021.001":   "RDP Lateral Movement",
            "T1021.002":   "SMB Lateral Movement",
            "T1021.003":   "DCOM Lateral Movement",
            "T1021.004":   "SSH Lateral Movement",
            "T1021.006":   "WinRM Lateral Movement",
            "T1563.002":   "RDP Session Hijacking",
            "T1570":       "Tool Transfer to Pivot",
            # Exfiltration / C2
            "T1041":       "Data Exfiltration",
            "T1537":       "Cloud Data Exfiltration",
            "T1071.001":   "HTTP/S C2 Channel",
            "T1071.002":   "FTP C2 Channel",
            "T1071.004":   "DNS C2 Channel",
            "T1102":       "Web Service C2",
            "T1105":       "Remote Tool Download",
            "T1573.001":   "Encrypted C2 (Symmetric)",
            "T1573.002":   "Encrypted C2 (Asymmetric)",
            # Initial Access
            "T1078":       "Valid Account Abuse",
            "T1189":       "Drive-by Compromise",
            "T1190":       "Web App Exploitation",
            "T1195.002":   "Supply Chain Compromise",
            "T1566.001":   "Phishing Attachment",
            "T1566.002":   "Phishing Link",
            "T1584":       "Infrastructure Compromise",
            "T1588.006":   "Vulnerability Exploitation",
            # Impact
            "T1485":       "Data Destruction",
            "T1486":       "Ransomware Encryption",
            "T1489":       "Service Disruption",
            "T1490":       "Recovery Inhibition",
            "T1496":       "Crypto Mining",
            "T1498":       "DDoS Attack",
            "T1498.002":   "Amplification DDoS",
            "T1529":       "System Shutdown",
        }
        return ctx.get(technique, "Unknown Context")

    def _impact(self, severity):
        return {"Critical":"Very High","High":"High","Medium":"Moderate","Low":"Low"}.get(severity, "Unknown")

    def _priority(self, row):
        return {
            "Critical": "Immediate Investigation",
            "High":     "High Priority",
            "Medium":   "Medium Priority",
            "Low":      "Low Priority",
        }.get(row["severity"], "Low Priority")