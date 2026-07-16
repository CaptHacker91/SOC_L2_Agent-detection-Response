import json


class FileLoader:
    """
    Load Blue Team Defense Dataset
    """

    def __init__(self, file_path):
        self.file_path = file_path

    def load(self):
        """
        Load JSONL dataset
        """

        records = []

        with open(
            self.file_path,
            "r",
            encoding="utf-8",
        ) as file:

            for line in file:

                records.append(
                    json.loads(line)
                )

        return records