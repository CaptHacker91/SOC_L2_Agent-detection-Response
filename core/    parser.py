class DetectionParser:
    """
    Parse Blue Team Defense Dataset
    """

    def parse(self, records):
        """
        Parse raw records into
        a standardized format.
        """

        parsed_records = []

        for record in records:

            parsed_records.append(
                {
                    "id": record.get(
                        "id",
                        0,
                    ),

                    "threat": record.get(
                        "threat",
                        "Unknown Threat",
                    ),

                    "rule_type": record.get(
                        "rule_type",
                        "Unknown",
                    ),

                    "signature": record.get(
                        "signature",
                        "Unknown",
                    ),

                    "tool": record.get(
                        "tool",
                        "Unknown",
                    ),

                    "mapped_technique": record.get(
                        "mapped_technique",
                        "Unknown",
                    ),
                }
            )

        return parsed_records