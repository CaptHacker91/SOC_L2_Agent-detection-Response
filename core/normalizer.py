import pandas as pd


class DataNormalizer:
    """
    Normalize Detection Dataset
    """

    def normalize(self, parsed_data):

        df = pd.DataFrame(parsed_data)

        df.columns = [

            column.lower()
            .strip()
            .replace(" ", "_")

            for column in df.columns
        ]

        df.fillna("", inplace=True)

        df.drop_duplicates(
            inplace=True
        )

        return df