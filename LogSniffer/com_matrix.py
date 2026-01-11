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

EXPECTED_HEADERS = [
    _KEY_UUID,
    _KEY_NAME,
    _KEY_ENCRYPTED,
    _KEY_MDT,
    _KEY_NOTES,
]


class GattThing:
    """
    Minimal shared base for GATT entities.
    UUIDs are stored normalized (lowercase, no dashes).
    """

    def __init__(self, uuid: str, name: str):
        self.uuid = uuid
        self.name = name

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(uuid={self.uuid}, name={self.name})"


class Service(GattThing):
    pass


class Characteristic(GattThing):
    """
    Characteristic bound to exactly one Service.
    Flags may be None when CSV marks them as unknown.
    """

    def __init__(
        self,
        uuid: str,
        name: str,
        encrypted: Optional[bool],
        proprietary: Optional[bool],
        notes: str,
        service: Service,
    ):
        super().__init__(uuid, name)
        self.encrypted = encrypted
        self.proprietary = proprietary
        self.notes = notes
        self.service = service

    def __repr__(self) -> str:
        return (
            f"Characteristic(uuid={self.uuid}, name={self.name}, "
            f"service={self.service.name})"
        )


class ComMatrixParser:
    def __init__(self, directory: str):
        self.directory = Path(directory)
        if not self.directory.is_dir():
            raise ValueError(f"Not a directory: {directory}")

        self.services_csv = self.directory / "_services.csv"
        if not self.services_csv.exists():
            raise FileNotFoundError("_services.csv not found")

    def parse(self) -> tuple[List[Characteristic], List[Service]]:
        characteristics: List[Characteristic] = []
        services: List[Service] = []

        with self.services_csv.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            for row_num, row in enumerate(reader, start=2):
                name = row[_SVC_NAME].strip()
                if "?" in name:
                    # Explicitly ignore unknown / placeholder services
                    continue

                uuid = self._parse_uuid(row[_SVC_UUID], "_services.csv", row_num)
                service = Service(uuid, name)
                services.append(service)

                csv_path = self.directory / f"{self._service_name_to_filename(name)}.csv"
                if not csv_path.exists():
                    raise FileNotFoundError(
                        f"{csv_path.name} not found (from service '{name}')"
                    )

                characteristics.extend(
                    self._parse_characteristics_csv(csv_path, service)
                )

        return characteristics, services

    # ---------------- helpers ----------------

    @staticmethod
    def _service_name_to_filename(name: str) -> str:
        """
        Prefer the explicit token in parentheses if present,
        otherwise derive a filesystem-safe name.
        """
        m = re.search(r"\(([^)]+)\)", name)
        if m:
            return m.group(1).strip().lower()
        return name.lower().replace(" ", "_")

    def _parse_characteristics_csv(
        self, path: Path, service: Service
    ) -> List[Characteristic]:
        results: List[Characteristic] = []

        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)

            # Strict header match: order and spelling matter here
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
                    self._parse_row(row, path.name, row_num, service)
                )

        return results

    def _parse_row(
        self,
        row: dict,
        filename: str,
        row_num: int,
        service: Service,
    ) -> Characteristic:
        uuid = self._parse_uuid(row[_KEY_UUID], filename, row_num)

        return Characteristic(
            uuid=uuid,
            name=row[_KEY_NAME].strip(),
            encrypted=self._parse_flag(
                row[_KEY_ENCRYPTED], _KEY_ENCRYPTED, filename, row_num
            ),
            proprietary=self._parse_flag(
                row[_KEY_MDT], _KEY_MDT, filename, row_num
            ),
            notes=row[_KEY_NOTES].strip(),
            service=service,
        )

    @staticmethod
    def _parse_uuid(value: str, filename: str, row_num: int) -> str:
        """
        Enforces 128-bit UUIDs only (no short UUID expansion here).
        """
        uuid = value.strip().lower().replace("-", "")
        if len(uuid) != 32 or not all(c in "0123456789abcdef" for c in uuid):
            raise ValueError(f"{filename}:{row_num} invalid UUID '{value}'")
        return uuid

    @staticmethod
    def _parse_flag(
        value: str, field: str, filename: str, row_num: int
    ) -> Optional[bool]:
        """
        yes/no/? → True/False/None
        """
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
    chars, servs = parser.parse()

    for c in chars:
        print(c)
    print(f"Parsed {len(chars)} characteristics")

    for s in servs:
        print(s)
    print(f"Parsed {len(servs)} services")
