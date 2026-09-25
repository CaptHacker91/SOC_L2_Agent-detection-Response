class DetectionParser:
    """
    Parse Splunk export records.
    Preserves every original Splunk field.
    """

    def parse(self, records):
        parsed_records = []

        for record in records:
            # Splunk export may be:
            # {"preview": false, "result": {...}}
            if isinstance(record, dict) and "result" in record:
                event = record["result"]
            else:
                event = record

            if isinstance(event, dict):
                parsed_records.append(dict(event))

        return parsed_records
