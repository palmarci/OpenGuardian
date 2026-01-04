import csv
from pathlib import Path
from typing import List, Optional

EXPECTED_HEADERS = [
    "UUID",
    "Name",
    "Encrypted",
    "Medtronic Proprietary",
    "Notes",
]

class Characteristic:
    def __init__(
        self,
        uuid: str,
        name: str,
        encrypted: Optional[bool],
        proprietary: Optional[bool],
        notes: str,
    ):
        self.uuid = uuid
        self.name = name
        self.encrypted = encrypted
        self.proprietary = proprietary
        self.notes = notes

    def __repr__(self):
        return (
            f"Characteristic(uuid={self.uuid}, name={self.name}, "
            f"encrypted={self.encrypted}, proprietary={self.proprietary})"
        )

class ComMatrixParser():

    def __init__(self, directory: str):
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

    def parse(self) -> List[Characteristic]:
        characteristics: List[Characteristic] = []

        for csv_file in self.directory.glob("*.csv"):
            if csv_file.name.startswith("_"):
                continue

            characteristics.extend(self._parse_csv(csv_file))

        return characteristics

    def _parse_csv(self, path: Path) -> List[Characteristic]:
        results: List[Characteristic] = []

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames != EXPECTED_HEADERS:
                raise ValueError(
                    f"{path.name}: invalid headers {reader.fieldnames}, "
                    f"expected {EXPECTED_HEADERS}"
                )

            for row_num, row in enumerate(reader, start=2):
                results.append(self._parse_row(row, path.name, row_num))

        return results

    def _parse_row(
        self, row: dict, filename: str, row_num: int
    ) -> Characteristic:
        uuid = self._parse_uuid(row["UUID"], filename, row_num)
        name = self._parse_name(row["Name"], filename, row_num)
        encrypted = self._parse_flag(row["Encrypted"], "Encrypted", filename, row_num)
        proprietary = self._parse_flag(
            row["Medtronic Proprietary"], "Medtronic Proprietary", filename, row_num
        )
        notes = row["Notes"].strip()

        return Characteristic(uuid, name, encrypted, proprietary, notes)

    def _parse_uuid(self, value: str, filename: str, row_num: int) -> str:
        uuid = value.strip().lower().replace("-", "")

        if len(uuid) != 32:
            raise ValueError(
                f"{filename}:{row_num} UUID must be 32 chars after cleanup, got '{uuid}'"
            )

        if not all(c in "0123456789abcdef" for c in uuid):
            raise ValueError(
                f"{filename}:{row_num} UUID contains non-hex characters: '{uuid}'"
            )

        return uuid

    def _parse_name(self, value: str, filename: str, row_num: int) -> str:
        name = value.strip()

        if "?" in name:
            return name

        if len(name) < 2:
            raise ValueError(
                f"{filename}:{row_num} Name must be at least 2 characters"
            )

        return name

    def _parse_flag(
        self, value: str, field: str, filename: str, row_num: int
    ) -> Optional[bool]:
        v = value.strip().lower()

        if "?" in v:
            return None
        if v == "yes":
            return True
        if v == "no":
            return False

        raise ValueError(
            f"{filename}:{row_num} {field} must be 'yes', 'no', or contain '?'"
        )
