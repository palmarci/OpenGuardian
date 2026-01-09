import csv
from pathlib import Path
from typing import List, Optional

_KEY_UUID = "UUID"
_KEY_NAME = "Name"
_KEY_ENCRYPTED = "Encrypted"
_KEY_MDT = "Medtronic Proprietary"
_KEY_NOTES = "Notes"
_KEY_CONVERTER = "Converter Class"

EXPECTED_HEADERS = [
    _KEY_UUID,
    _KEY_NAME,
    _KEY_ENCRYPTED,
    _KEY_MDT,
    _KEY_NOTES,
    _KEY_CONVERTER,
]

class Characteristic:
    def __init__(
        self,
        uuid: str,
        name: str,
        encrypted: Optional[bool],
        proprietary: Optional[bool],
        notes: str,
        converter_class: str,
    ):
        self.uuid = uuid
        self.name = name
        self.encrypted = encrypted
        self.proprietary = proprietary
        self.notes = notes
        self.converter_class = converter_class

    def __repr__(self):
        return (
            f"Characteristic(uuid={self.uuid}, name={self.name}, "
            f"encrypted={self.encrypted}, proprietary={self.proprietary}, "
            f"converter_class={self.converter_class})"
        )

class ComMatrixParser:
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
        uuid = self._parse_uuid(row[_KEY_UUID], filename, row_num)
        name = self._parse_name(row[_KEY_NAME], filename, row_num)
        encrypted = self._parse_flag(row[_KEY_ENCRYPTED], _KEY_ENCRYPTED, filename, row_num)
        proprietary = self._parse_flag(row[_KEY_MDT], _KEY_MDT, filename, row_num)
        notes = row[_KEY_NOTES].strip()
        converter_class = row[_KEY_CONVERTER].strip()

        return Characteristic(uuid, name, encrypted, proprietary, notes, converter_class)

    def _parse_uuid(self, value: str, filename: str, row_num: int) -> str:
        uuid = value.strip().lower().replace("-", "")
        if len(uuid) != 32:
            raise ValueError(f"{filename}:{row_num} UUID must be 32 chars after cleanup, got '{uuid}'")
        if not all(c in "0123456789abcdef" for c in uuid):
            raise ValueError(f"{filename}:{row_num} UUID contains non-hex characters: '{uuid}'")
        return uuid

    def _parse_name(self, value: str, filename: str, row_num: int) -> str:
        name = value.strip()
        if "?" in name:
            return name
        if len(name) < 2:
            raise ValueError(f"{filename}:{row_num} Name must be at least 2 characters")
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
        raise ValueError(f"{filename}:{row_num} {field} must be 'yes', 'no', or contain '?'")
