import json


class DetectionEngine:
    """
    Evidence-based classifier. Every row gets:
        threat, detection_reason, rule_type, tool, final_detection

    final_detection is 'Normal' or 'Anomaly' here — AlertTriangle
    (the next stage) may upgrade 'Anomaly' to 'Confirmed Threat'
    once severity is known.

    Branches by event_category (set by core/parser.py):
      - vendor_sales   -> ALWAYS Normal. Business telemetry must never
                          be auto-flagged as malicious.
      - web_access     -> HTTP status + URI pattern rules, each with
                          an explicit, documented reason. A 404/403/5xx
                          is never described as a confirmed attack —
                          only as what it actually is.
      - synthetic_soc  -> rules/detection_rules.json signature match,
                          else flagged as an unmatched anomaly. This
                          keeps BLUE_TEAM_DEFENSE_DATASET.jsonl working
                          exactly as before, without depending on
                          IsolationForest/LocalOutlierFactor, which
                          was the actual source of instability when
                          real Splunk data was run through the old code.
      - other          -> Normal, generic label. Never guessed at.
    """

    SUSPICIOUS_URI_PATTERNS = [
        "..", "/etc/passwd", "select ", "union select", "<script",
        "cmd.exe", "/bin/sh", "wp-admin", ".php?", "eval(",
    ]

    # status -> (threat label, detection reason). Reason always states
    # what the status code actually means — never "confirmed attack".
    ANOMALOUS_STATUS_REASONS = {
        400: ("Malformed Web Request", "HTTP 400 Bad Request — client sent a malformed or invalid request."),
        403: ("Access Denied Attempt", "HTTP 403 Forbidden — request denied by server; possible unauthorized access attempt."),
        404: ("Suspicious Resource Access Attempt", "HTTP 404 response to requested resource; resource not found, access/transfer not confirmed."),
        406: ("Not Acceptable Request", "HTTP 406 — requested content type not acceptable to server."),
        408: ("Request Timeout", "HTTP 408 — client request timed out."),
        500: ("Server Error on Request", "HTTP 500 Internal Server Error in response to request; may indicate an application fault, exploitation not confirmed."),
        503: ("Service Unavailable", "HTTP 503 — server temporarily unavailable when the request was made."),
        505: ("Protocol Version Error", "HTTP 505 — HTTP version not supported by server."),
    }

    def __init__(self, rules_path=None):
        self.rules = []
        if rules_path:
            try:
                with open(rules_path, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                self.rules = []
        self._rule_map = {r["threat"]: r for r in self.rules if "threat" in r}

    def analyze(self, df):
        if df.empty:
            return df

        rows = [self._classify_row(row) for _, row in df.iterrows()]
        df["threat"]           = [r[0] for r in rows]
        df["detection_reason"] = [r[1] for r in rows]
        df["rule_type"]        = [r[2] for r in rows]
        df["tool"]             = [r[3] for r in rows]
        df["final_detection"]  = [r[4] for r in rows]
        return df

    def _classify_row(self, row):
        category = row.get("event_category", "other")

        if category == "vendor_sales":
            return ("Vendor Sales Record", "Business telemetry; not a security event.",
                    "Business Rule", "Vendor Feed", "Normal")

        if category == "web_access":
            return self._classify_web(row)

        if category == "synthetic_soc":
            return self._classify_synthetic(row)

        return ("Unclassified Event", "Event does not match a known category.", "None", "None", "Normal")

    def _classify_synthetic(self, row):
        threat = row.get("threat")
        if threat in self._rule_map:
            return (threat, f"Matched detection rule signature for '{threat}'.",
                    "Signature Match", row.get("tool", "Rule Engine"), "Anomaly")
        return (threat or "Unclassified Event",
                "No matching rule signature for this threat label.",
                row.get("rule_type", "Heuristic"), row.get("tool", "Detection Engine"), "Anomaly")

    def _classify_web(self, row):
        status_raw = row.get("http_status")
        uri = str(row.get("url") or row.get("uri_path") or "").lower()
        suspicious_pattern = any(p in uri for p in self.SUSPICIOUS_URI_PATTERNS)

        try:
            status = int(status_raw) if status_raw is not None and str(status_raw) != "nan" else None
        except (ValueError, TypeError):
            status = None

        if suspicious_pattern:
            if status == 200:
                reason = ("Request URI matches a known suspicious pattern AND the request "
                          "succeeded (HTTP 200) — potential successful exploitation attempt.")
                return ("Suspicious Request Pattern (Success)", reason,
                        "HTTP Anomaly Detection", "Web Access Log", "Anomaly")
            reason = (f"Request URI matches a known suspicious pattern; server responded "
                      f"HTTP {status} — outcome not confirmed.")
            return ("Suspicious Request Pattern", reason,
                    "HTTP Anomaly Detection", "Web Access Log", "Anomaly")

        if status in self.ANOMALOUS_STATUS_REASONS:
            threat, reason = self.ANOMALOUS_STATUS_REASONS[status]
            return (threat, reason, "HTTP Anomaly Detection", "Web Access Log", "Anomaly")

        return ("Normal Web Access", f"HTTP {status} — routine web access.",
                "Baseline", "Web Access Log", "Normal")
