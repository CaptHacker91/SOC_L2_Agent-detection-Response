class DetectionParser:
    """
    Light validation + event-type tagging.

    Keeps every original field untouched. Only drops genuinely empty
    rows and adds one new field, event_category, so downstream stages
    (normalizer, detection engine) can branch cleanly between:

      - "vendor_sales"   business telemetry (tutorialdata vendor_sales.log)
      - "web_access"     access_combined_wcookie web logs
      - "synthetic_soc"  the original BLUE_TEAM_DEFENSE_DATASET rows
      - "other"          anything that doesn't match a known shape
    """

    def parse(self, raw_records):
        parsed = []
        for rec in raw_records:
            if not isinstance(rec, dict) or not rec:
                continue
            rec = dict(rec)  # don't mutate the caller's data
            rec["event_category"] = self._categorize(rec)
            parsed.append(rec)
        return parsed

    def _categorize(self, rec):
        sourcetype = str(rec.get("sourcetype", "")).lower()
        host = str(rec.get("host", "")).lower()

        if "vendor_sales" in sourcetype or host == "vendor_sales":
            return "vendor_sales"

        if "access_combined" in sourcetype or "clientip" in rec or "uri" in rec:
            return "web_access"

        if "threat" in rec and "signature" in rec:
            return "synthetic_soc"

        return "other"
