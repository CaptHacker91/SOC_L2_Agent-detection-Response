class DetectionParser:
    """
    Parse Detection Dataset
    """

    def parse(self, records):

        parsed = []

        for record in records:

            parsed.append({

                "id":
                record.get("id", ""),

                "threat":
                record.get("threat", "Unknown Threat"),

                "description":
                record.get("description", ""),

                "rule_type":
                record.get("rule_type", ""),

                "signature":
                record.get("signature", ""),

                "tool":
                record.get("tool", ""),

                "mapped_technique":
                record.get("mapped_technique", "")

            })

        return parsed