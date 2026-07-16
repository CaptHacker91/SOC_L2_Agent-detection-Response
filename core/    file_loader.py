import json
from pathlib import Path


class FileLoader:
    """
    Load Blue Team Detection Dataset
    """

    def __init__(self, file_path):
        self.file_path = Path(file_path)

    def load(self):

        if not self.file_path.exists():
            raise FileNotFoundError(
                f"Dataset not found : {self.file_path}"
            )

        records = []

        with open(
            self.file_path,
            "r",
            encoding="utf-8"
        ) as file:

            for line in file:

                line = line.strip()

                if line:

                    try:
                        records.append(
                            json.loads(line)
                        )

                    except json.JSONDecodeError:
                        continue

        return records