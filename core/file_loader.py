import json


class FileLoader:
    """
    Load JSON / JSONL telemetry while preserving the original event fields.
    """

    def __init__(self, file_path):
        self.file_path = file_path

    def load(self):
        with open(self.file_path, "r", encoding="utf-8") as file:
            content = file.read().strip()

        if not content:
            return []

        # Normal JSON
        try:
            data = json.loads(content)

            if isinstance(data, list):
                return data

            if isinstance(data, dict):
                return [data]

        except json.JSONDecodeError:
            pass

        # JSONL fallback
        records = []

        for line in content.splitlines():
            line = line.strip()

            if not line:
                continue

            records.append(json.loads(line))

        return records
