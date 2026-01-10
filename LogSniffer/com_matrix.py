import csv
import re
from pathlib import Path
from typing import List, Optional


# ---- service CSV keys ----
_SVC_UUID = "Service UUID"
_SVC_NAME = "Service Name"


# ---- characteristic CSV keys ----
_KEY_UUID = "UUID"
_KEY_NAME = "Name"
_KEY_ENCRYPTED = "Encrypted"
_KEY_MDT = "Medtronic Proprietary"
_KEY_NOTES = "Notes"
#_KEY_CONVERTER = "Converter Class"

EXPECTED_HEADERS = [
    _KEY_UUID,
    _KEY_NAME,
    _KEY_ENCRYPTED,
    _KEY_MDT,
    _KEY_NOTES,
#    _KEY_CONVERTER,
]


class Characteristic:
    def __init__(
        self,
        uuid: str,
        name: str,
        encrypted: Optional[bool],
        proprietary: Optional[bool],
        notes: str,
      #  converter_class: str,
        service_uuid: str,
    ):
        self.uuid = uuid
        self.name = name
        self.encrypted = encrypted
        self.proprietary = proprietary
        self.notes = notes
    #    self.converter_class = converter_class
        self.service_uuid = service_uuid

    def __repr__(self):
        return (
            f"Characteristic(uuid={self.uuid}, name={self.name}, "
            f"service_uuid={self.service_uuid})"
        )


class ComMatrixParser:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        self.services_csv = self.directory / "_services.csv"
        if not self.services_csv.exists():
            raise ValueError("_services.csv not found")

    def parse(self) -> List[Characteristic]:
        characteristics: List[Characteristic] = []

        with self.services_csv.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, start=2):
                service_name = row[_SVC_NAME].strip()
                if "?" in service_name:
                    continue

                service_uuid = self._parse_uuid(
                    row[_SVC_UUID], "_services.csv", row_num
                )

                filename = self._service_name_to_filename(service_name)
                csv_path = self.directory / f"{filename}.csv"

                if not csv_path.exists():
                    raise FileNotFoundError(
                        f"{csv_path.name} not found (from service '{service_name}')"
                    )

                characteristics.extend(
                    self._parse_characteristics_csv(csv_path, service_uuid)
                )

        return characteristics

    # ---------------- helpers ----------------

    def _service_name_to_filename(self, name: str) -> str:
        m = re.search(r"\(([^)]+)\)", name)
        if m:
            return m.group(1).strip().lower()

        return name.lower().replace(" ", "_")

    def _parse_characteristics_csv(
        self, path: Path, service_uuid: str
    ) -> List[Characteristic]:
        results: List[Characteristic] = []

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            if reader.fieldnames != EXPECTED_HEADERS:
                raise ValueError(
                    f"{path.name}: invalid headers {reader.fieldnames}, "
                    f"expected {EXPECTED_HEADERS}"
                )

            for row_num, row in enumerate(reader, start=2):
                name = row[_KEY_NAME].strip()
                if "?" in name:
                    continue

                results.append(
                    self._parse_row(row, path.name, row_num, service_uuid)
                )

        return results

    def _parse_row(
        self,
        row: dict,
        filename: str,
        row_num: int,
        service_uuid: str,
    ) -> Characteristic:
        uuid = self._parse_uuid(row[_KEY_UUID], filename, row_num)
        name = row[_KEY_NAME].strip()
        encrypted = self._parse_flag(
            row[_KEY_ENCRYPTED], _KEY_ENCRYPTED, filename, row_num
        )
        proprietary = self._parse_flag(
            row[_KEY_MDT], _KEY_MDT, filename, row_num
        )
        notes = row[_KEY_NOTES].strip()
        #converter_class = row[_KEY_CONVERTER].strip()

        return Characteristic(
            uuid,
            name,
            encrypted,
            proprietary,
            notes,
           # converter_class,
            service_uuid,
        )

    def _parse_uuid(self, value: str, filename: str, row_num: int) -> str:
        uuid = value.strip().lower().replace("-", "")
        if len(uuid) != 32 or not all(c in "0123456789abcdef" for c in uuid):
            raise ValueError(f"{filename}:{row_num} invalid UUID '{value}'")
        return uuid

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
            f"{filename}:{row_num} {field} must be yes/no/?"
        )


# ---------------- test entry ----------------

if __name__ == "__main__":
    TEST_DIR = "/home/marci/projects/code/medtronic/repo/data/com_matrix/"
    parser = ComMatrixParser(TEST_DIR)
    chars = parser.parse()
    for c in chars:
        print(c)
    print(f"Parsed {len(chars)} characteristics")

