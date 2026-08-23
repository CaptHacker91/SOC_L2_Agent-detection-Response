class MitreMapper:
    """
    MITRE ATT&CK Mapping Engine
    Complete mapping for all 111 techniques in the dataset.
    """

    def __init__(self):
        self.mapping = self._load_mapping()

    def _load_mapping(self):
        return {
            # Execution
            "T1059":       ("Execution",            "Command & Scripting Interpreter"),
            "T1059.001":   ("Execution",            "PowerShell"),
            "T1059.005":   ("Execution",            "Visual Basic"),
            "T1059.006":   ("Execution",            "Python"),
            "T1059.007":   ("Execution",            "JavaScript"),
            "T1059.008":   ("Execution",            "Network Device CLI"),
            "T1047":       ("Execution",            "WMI Execution"),
            "T1204.001":   ("Execution",            "Malicious Link"),
            "T1204.002":   ("Execution",            "Malicious File"),

            # Persistence
            "T1547":       ("Persistence",          "Boot/Logon Autostart"),
            "T1547.001":   ("Persistence",          "Registry Run Keys"),
            "T1053":       ("Persistence",          "Scheduled Task"),
            "T1053.005":   ("Persistence",          "Scheduled Task/Job"),
            "T1543.003":   ("Persistence",          "Windows Service"),
            "T1546.003":   ("Persistence",          "WMI Event Subscription"),
            "T1546.012":   ("Persistence",          "Image File Execution Options"),
            "T1505":       ("Persistence",          "Server Software Component"),
            "T1505.003":   ("Persistence",          "Web Shell"),
            "T1505.004":   ("Persistence",          "IIS Components"),
            "T1574":       ("Persistence",          "Hijack Execution Flow"),
            "T1574.002":   ("Persistence",          "DLL Side-Loading"),
            "T1176":       ("Persistence",          "Browser Extensions"),

            # Privilege Escalation
            "T1068":       ("Privilege Escalation", "Exploitation for Privilege Escalation"),
            "T1134.001":   ("Privilege Escalation", "Token Impersonation/Theft"),
            "T1548.005":   ("Privilege Escalation", "Temporary Elevated Cloud Access"),

            # Defense Evasion
            "T1055":       ("Defense Evasion",      "Process Injection"),
            "T1055.001":   ("Defense Evasion",      "DLL Injection"),
            "T1055.012":   ("Defense Evasion",      "Process Hollowing"),
            "T1027":       ("Defense Evasion",      "Obfuscated Files or Info"),
            "T1027.002":   ("Defense Evasion",      "Software Packing"),
            "T1070.004":   ("Defense Evasion",      "File Deletion"),
            "T1218":       ("Defense Evasion",      "Signed Binary Proxy Execution"),
            "T1218.004":   ("Defense Evasion",      "InstallUtil"),
            "T1218.005":   ("Defense Evasion",      "Mshta"),
            "T1218.010":   ("Defense Evasion",      "Regsvr32"),
            "T1562":       ("Defense Evasion",      "Impair Defenses"),
            "T1562.008":   ("Defense Evasion",      "Disable Cloud Logs"),
            "T1553.002":   ("Defense Evasion",      "Code Signing"),
            "T1564.001":   ("Defense Evasion",      "Hidden Files and Directories"),
            "T1564.004":   ("Defense Evasion",      "NTFS File Attributes"),
            "T1014":       ("Defense Evasion",      "Rootkit"),
            "T1090.003":   ("Defense Evasion",      "Multi-hop Proxy"),

            # Credential Access
            "T1003":       ("Credential Access",    "OS Credential Dumping"),
            "T1003.001":   ("Credential Access",    "LSASS Memory Dump"),
            "T1003.002":   ("Credential Access",    "SAM Dump"),
            "T1110":       ("Credential Access",    "Brute Force"),
            "T1110.004":   ("Credential Access",    "Credential Stuffing"),
            "T1056.001":   ("Credential Access",    "Keylogging"),
            "T1056.002":   ("Credential Access",    "GUI Input Capture"),
            "T1552.005":   ("Credential Access",    "Cloud Instance Metadata"),
            "T1552.007":   ("Credential Access",    "Container API"),
            "T1558.001":   ("Credential Access",    "Golden Ticket"),
            "T1558.002":   ("Credential Access",    "Silver Ticket"),
            "T1550.001":   ("Credential Access",    "Application Access Token"),
            "T1550.002":   ("Credential Access",    "Pass the Hash"),
            "T1550.003":   ("Credential Access",    "Pass the Ticket"),
            "T1550.004":   ("Credential Access",    "Web Session Cookie"),

            # Discovery
            "T1082":       ("Discovery",            "System Information Discovery"),
            "T1083":       ("Discovery",            "File and Directory Discovery"),
            "T1033":       ("Discovery",            "System Owner/User Discovery"),
            "T1049":       ("Discovery",            "System Network Connections"),
            "T1046":       ("Discovery",            "Network Service Discovery"),
            "T1018":       ("Discovery",            "Remote System Discovery"),
            "T1057":       ("Discovery",            "Process Discovery"),
            "T1007":       ("Discovery",            "System Service Discovery"),
            "T1012":       ("Discovery",            "Query Registry"),
            "T1016":       ("Discovery",            "System Network Config Discovery"),
            "T1016.001":   ("Discovery",            "Internet Connection Discovery"),
            "T1040":       ("Discovery",            "Network Sniffing"),
            "T1135":       ("Discovery",            "Network Share Discovery"),
            "T1069.001":   ("Discovery",            "Local Groups"),
            "T1069.002":   ("Discovery",            "Domain Groups"),
            "T1087.001":   ("Discovery",            "Local Account Discovery"),
            "T1087.004":   ("Discovery",            "Cloud Account Discovery"),
            "T1518.001":   ("Discovery",            "Security Software Discovery"),
            "T1526":       ("Discovery",            "Cloud Service Discovery"),
            "T1613":       ("Discovery",            "Container and Resource Discovery"),

            # Lateral Movement
            "T1021":       ("Lateral Movement",     "Remote Services"),
            "T1021.001":   ("Lateral Movement",     "Remote Desktop Protocol"),
            "T1021.002":   ("Lateral Movement",     "SMB/Windows Admin Shares"),
            "T1021.003":   ("Lateral Movement",     "DCOM"),
            "T1021.004":   ("Lateral Movement",     "SSH"),
            "T1021.006":   ("Lateral Movement",     "Windows Remote Management"),
            "T1563.002":   ("Lateral Movement",     "RDP Hijacking"),
            "T1570":       ("Lateral Movement",     "Lateral Tool Transfer"),

            # Collection
            "T1041":       ("Exfiltration",         "Exfiltration Over C2 Channel"),
            "T1537":       ("Exfiltration",         "Transfer Data to Cloud Account"),

            # Command and Control
            "T1071":       ("Command and Control",  "Application Layer Protocol"),
            "T1071.001":   ("Command and Control",  "Web Protocols"),
            "T1071.002":   ("Command and Control",  "File Transfer Protocols"),
            "T1071.004":   ("Command and Control",  "DNS"),
            "T1102":       ("Command and Control",  "Web Service"),
            "T1105":       ("Command and Control",  "Ingress Tool Transfer"),
            "T1573.001":   ("Command and Control",  "Symmetric Cryptography"),
            "T1573.002":   ("Command and Control",  "Asymmetric Cryptography"),

            # Initial Access
            "T1078":       ("Initial Access",       "Valid Accounts"),
            "T1189":       ("Initial Access",       "Drive-by Compromise"),
            "T1190":       ("Initial Access",       "Exploit Public-Facing Application"),
            "T1195.002":   ("Initial Access",       "Compromise Software Supply Chain"),
            "T1566.001":   ("Initial Access",       "Spearphishing Attachment"),
            "T1566.002":   ("Initial Access",       "Spearphishing Link"),
            "T1584":       ("Initial Access",       "Compromise Infrastructure"),
            "T1588.006":   ("Initial Access",       "Vulnerabilities"),

            # Impact
            "T1485":       ("Impact",               "Data Destruction"),
            "T1486":       ("Impact",               "Data Encrypted for Impact"),
            "T1489":       ("Impact",               "Service Stop"),
            "T1490":       ("Impact",               "Inhibit System Recovery"),
            "T1496":       ("Impact",               "Resource Hijacking"),
            "T1498":       ("Impact",               "Network Denial of Service"),
            "T1498.002":   ("Impact",               "Reflection Amplification"),
            "T1529":       ("Impact",               "System Shutdown/Reboot"),

            # Cloud-specific
            "T1610":       ("Defense Evasion",      "Deploy Container"),
            "T1611":       ("Privilege Escalation", "Escape to Host"),
            "T1484.001":   ("Defense Evasion",      "Group Policy Modification"),
            "T1484.002":   ("Defense Evasion",      "Domain Policy Modification"),
        }

    def map(self, dataframe):
        dataframe["mitre_tactic"]   = dataframe["mapped_technique"].apply(self._get_tactic)
        dataframe["mitre_sub_name"] = dataframe["mapped_technique"].apply(self._get_sub_name)
        return dataframe

    def _get_tactic(self, technique):
        entry = self.mapping.get(technique)
        return entry[0] if entry else "Unknown"

    def _get_sub_name(self, technique):
        entry = self.mapping.get(technique)
        return entry[1] if entry else "Unknown Technique"