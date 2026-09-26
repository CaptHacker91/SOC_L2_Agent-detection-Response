import json


class FileLoader:
    """
    Loads a local dataset file for the SOC pipeline.

    Handles three real-world shapes so the SAME loader works for both
    the old synthetic dataset and a static Splunk export, whichever
    format it was saved in:

      1. A plain JSON array:            [ {...}, {...}, ... ]
      2. A wrapped object with a list:  { "results": [ {...}, ... ] }
         (also tries "events" / "data" / "records" as the key)
      3. JSONL — one JSON object per line (the original format used
         by BLUE_TEAM_DEFENSE_DATASET.jsonl)

    Splunk's job/REST export sometimes wraps each event as
    {"preview": false, "result": {...fields...}} — that wrapper is
    unwrapped automatically so callers always get the flat event dict.

    This file does NOT interpret or rename any fields — that is
    core/normalizer.py's job. This layer only guarantees a clean
    list[dict] regardless of which export format was used.
    """

    def __init__(self, file_path):
        self.file_path = file_path

    def load(self):
        with open(self.file_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return []

        try:
            parsed = json.loads(content)
            return self._extract_records(parsed)
        except json.JSONDecodeError:
            pass

        records = []
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(self._unwrap(json.loads(line)))
            except json.JSONDecodeError:
                continue
        return records

    def _extract_records(self, parsed):
        if isinstance(parsed, list):
            return [self._unwrap(r) for r in parsed]
        if isinstance(parsed, dict):
            for key in ("results", "events", "data", "records"):
                if key in parsed and isinstance(parsed[key], list):
                    return [self._unwrap(r) for r in parsed[key]]
            return [self._unwrap(parsed)]
        return []

    def _unwrap(self, obj):
        if isinstance(obj, dict) and isinstance(obj.get("result"), dict):
            return obj["result"]
        return obj
