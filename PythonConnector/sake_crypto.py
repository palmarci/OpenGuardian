from dataclasses import dataclass

from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC

import logging

# an enormous thank you to planiitis! https://github.com/planiitis/medtronic-bt-decrypt

def auth8(client_key_material, server_key_material, derivation_key, handshake_auth_key):
    msg = server_key_material + client_key_material + derivation_key
    assert len(msg) == 32
    cobj = CMAC.new(handshake_auth_key, ciphermod=AES, mac_len=8)
    cobj.update(msg)
    return cobj


@dataclass
class StaticKeys:
    derivation_key: bytes
    handshake_auth_key: bytes
    permit_decrypt_key: bytes
    permit_auth_key: bytes
    handshake_payload: bytes

    @staticmethod
    def from_bytes(data: bytes):
        return StaticKeys(*[data[i : i + 16] for i in range(0, 80, 16)])


@dataclass
class KeyDatabase:
    local_device_type: int
    remote_devices: dict[int, StaticKeys]

    @classmethod
    def from_bytes(cls, data: bytes):
        log = logging.getLogger(cls.__name__).getChild("from_bytes")
        n = data[5]
        if len(data) != 6 + 81 * n:
            raise ValueError
        local_device_type = data[4]
        log.debug(f"{local_device_type = }")
        remote_devices = {}
        for i in range(n):
            p = 6 + 81 * i
            remote_devices[data[p]] = StaticKeys.from_bytes(data[p + 1 : p + 81])
        log.debug(f"{remote_devices.keys() = }")
        return cls(local_device_type=local_device_type, remote_devices=remote_devices)


@dataclass
class SeqCrypt:
    key: bytes
    nonce: bytes
    seq: int

    def __post_init__(self):
        self.logger = logging.getLogger(type(self).__name__)
        if len(self.nonce) != 8:
            raise ValueError

    def decrypt(self, msg):
        log = self.logger.getChild("decrypt")
        if len(msg) < 3:
            raise ValueError
        d = (msg[-3] - self.seq // 2) & 0xFF
        seq = self.seq + 2 * d
        log.debug(f"{seq = }")
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        ciphertext = msg[:-3]
        log.debug(f"{ciphertext.hex() = }")
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        log.debug(f"{msg[-2:].hex() = }, {cobj.digest().hex() = }")
        cobj.verify(msg[-2:] + cobj.digest()[2:4])
        self.seq = seq + 2
        return AES.new(self.key, AES.MODE_CTR, nonce=nonce).decrypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt `plaintext` and produce the on-wire frame: ciphertext || seq_byte || mac_first2bytes

        This mirrors `decrypt` semantics: the on-wire trailer's first byte is `seq//2 & 0xFF`.
        After producing the frame, the internal `seq` is advanced by 2 (same as on receive).
        """
        log = self.logger.getChild("encrypt")
        seq = self.seq
        nonce = seq.to_bytes(length=5, byteorder="big") + self.nonce
        cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        cobj = CMAC.new(self.key, ciphermod=AES, mac_len=4)
        cobj.update(nonce.ljust(16, b"\0") + ciphertext)
        digest = cobj.digest()
        trailer = bytes([(seq // 2) & 0xFF]) + digest[:2]
        self.seq = seq + 2
        log.debug(f"encrypt: seq={seq} nonce={nonce.hex()} ciphertext={ciphertext.hex()} trailer={trailer.hex()}")
        return ciphertext + trailer


@dataclass
class Session:
    client_key_database: KeyDatabase | None = None
    server_key_database: KeyDatabase | None = None
    client_key_material: bytes | None = None
    client_nonce: bytes | None = None
    client_device_type: int | None = None
    server_device_type: int | None = None
    server_key_material: bytes | None = None
    server_nonce: bytes | None = None
    client_static_keys: StaticKeys | None = None
    server_static_keys: StaticKeys | None = None
    derivation_key: bytes | None = None
    handshake_auth_key: bytes | None = None
    client_crypt: SeqCrypt | None = None
    server_crypt: SeqCrypt | None = None

    def __post_init__(self):
        self.logger = logging.getLogger(type(self).__name__)

    def handshake_0_s(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        if msg[1] != 1:
            raise ValueError
        self.server_device_type = msg[0]

    def handshake_1_c(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        self.client_key_material = msg[:8]
        self.client_nonce = msg[9:13]
        cdt = self.client_device_type = msg[8]
        sdt = self.server_device_type
        sk = None
        ckd = self.client_key_database
        skd = self.server_key_database
        if ckd is None and skd is None:
            raise ValueError("No key database available.")
        if ckd is not None and ckd.local_device_type == cdt:
            sk = self.client_static_keys = ckd.remote_devices.get(sdt)
        if skd is not None and skd.local_device_type == sdt:
            sk = self.server_static_keys = skd.remote_devices.get(cdt)
        if sk is None:
            raise KeyError(f"No keys available for client device type {cdt} and server device type {sdt}.")
        self.derivation_key = sk.derivation_key
        self.handshake_auth_key = sk.handshake_auth_key


    def handshake_2_s(self, msg: bytes):
        if len(msg) != 20:
            raise ValueError
        server_key_material = msg[8:16]
        server_nonce = msg[16:20]
        auth = auth8(
            self.client_key_material,
            server_key_material,
            self.derivation_key,
            self.handshake_auth_key,
        )
        received = msg[0:8]
        auth.verify(received)
        self.server_key_material = server_key_material
        self.server_nonce = server_nonce

    def handshake_3_c(self, msg: bytes):
        log = self.logger.getChild("handshake_3_c")
        if len(msg) != 20:
            raise ValueError
        auth1 = auth8(
            self.client_key_material,
            self.server_key_material,
            self.derivation_key,
            self.handshake_auth_key,
        )
        inner = (
            auth1.digest() + self.server_key_material + self.derivation_key
        )
        auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        received = msg[:8]
        auth2.verify(received)
        log.info("verified")

    # --- helpers to build/compute handshake messages (new) ---
    def build_handshake_2_s(self, server_key_material: bytes, server_nonce: bytes) -> bytes:
        """
        Build the server -> client handshake_2 (20 bytes):
          [0:8]   = CMAC8(handshake_auth_key, server_key_material || client_key_material || derivation_key)
          [8:16]  = server_key_material (8 bytes)
          [16:20] = server_nonce (4 bytes)
        Requires that client_key_material, derivation_key and handshake_auth_key are already set.
        """
        if self.client_key_material is None or self.derivation_key is None or self.handshake_auth_key is None:
            raise ValueError("missing session state for building handshake_2")
        if len(server_key_material) != 8 or len(server_nonce) != 4:
            raise ValueError("server_key_material must be 8 bytes and server_nonce 4 bytes")
        auth = auth8(self.client_key_material, server_key_material, self.derivation_key, self.handshake_auth_key)
        return auth.digest() + server_key_material + server_nonce

    def compute_handshake_3_prefix(self) -> bytes:
        """
        Compute the first 8 bytes of the client -> server handshake_3 message.
        This is the CMAC8 over (auth1.digest() || server_key_material || derivation_key)
        """
        if None in (self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key):
            raise ValueError("missing session state for computing handshake_3")
        auth1 = auth8(self.client_key_material, self.server_key_material, self.derivation_key, self.handshake_auth_key)
        inner = auth1.digest() + self.server_key_material + self.derivation_key
        auth2 = CMAC.new(self.handshake_auth_key, ciphermod=AES, mac_len=8)
        auth2.update(inner)
        return auth2.digest()

    def build_handshake_3_c(self, filler: bytes | None = None) -> bytes:
        """
        Build a full 20-byte handshake_3 message.
        By protocol only the first 8 bytes are verified; filler fills remaining 12 bytes.
        If filler is None it will be zeroes. Provide filler when replaying captures.
        """
        prefix = self.compute_handshake_3_prefix()
        if filler is None:
            filler = bytes(12)
        if len(filler) != 12:
            raise ValueError("filler must be 12 bytes")
        return prefix + filler

    def build_handshake_5_c(self, payload16: bytes | None = None) -> bytes:
        """Build a client -> server encrypted handshake_5 message.

        The encrypted frame contains 17 bytes of plaintext: the 16-byte payload
        followed by one padding byte (0). If `payload16` is None, and the
        session has `client_static_keys` or `server_static_keys`, the code will
        attempt to use the `handshake_payload` where appropriate; otherwise
        a zeroed 16-byte payload is used.
        """
        if self.client_crypt is None:
            raise ValueError("client_crypt not initialized; call handshake_4_s first")
        if payload16 is None:
            # default payload: try to use prover static payload if available
            if self.client_static_keys is not None:
                payload16 = self.client_static_keys.handshake_payload
            else:
                payload16 = bytes(16)
        if len(payload16) != 16:
            raise ValueError("payload16 must be 16 bytes")
        plaintext = payload16 + b"\x00"
        return self.client_crypt.encrypt(plaintext)
    
    def handshake_4_s(self, msg: bytes):
        log = self.logger.getChild("handshake_4_s")
        if len(msg) != 20:
            raise ValueError
        key = AES.new(self.derivation_key, AES.MODE_ECB).encrypt(
            self.server_key_material + self.client_key_material
        )
        nonce = self.client_nonce + self.server_nonce
        log.debug(f"{nonce.hex() = }")
        self.client_crypt = SeqCrypt(key=key, nonce=nonce, seq=0)
        self.server_crypt = SeqCrypt(key=key, nonce=nonce, seq=1)
        inner = self.server_crypt.decrypt(msg)[:16]
        log.debug(f"{inner.hex() = }")
        self.check_payload(inner, self.client_static_keys, self.server_static_keys, self.server_device_type)

    def handshake_5_c(self, msg: bytes):
        log = self.logger.getChild("handshake_5_c")
        if len(msg) != 20:
            raise ValueError
        inner = self.client_crypt.decrypt(msg)[:-1]
        log.debug(f"{inner.hex() = }")
        self.check_payload(inner, self.server_static_keys, self.client_static_keys, self.client_device_type)


    @staticmethod
    def parse_handshake_2(msg: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Parse a handshake_2 (20 bytes) and return (received_mac8, server_key_material(8), server_nonce(4))
        """
        if len(msg) != 20:
            raise ValueError("handshake_2 message must be 20 bytes")
        return msg[:8], msg[8:16], msg[16:20]
    

    def check_payload(self, payload, verifier_static_keys, prover_static_keys, prover_device_type):
        log = self.logger.getChild("check_payload")
        if prover_static_keys is not None:
            log.debug(f"{payload.hex() = }")
            log.debug(f"{prover_static_keys.handshake_payload.hex() = }")
            if payload == prover_static_keys.handshake_payload:
                log.info("handshake payload match")
        if verifier_static_keys is not None:
            plain = AES.new(verifier_static_keys.permit_decrypt_key, AES.MODE_ECB).decrypt(
                payload
            )
            auth = CMAC.new(verifier_static_keys.permit_auth_key, ciphermod=AES, mac_len=4)
            auth.update(plain[:12])
            log.debug(f"{plain[:12].hex() = }")
            log.debug(f"{plain[12:].hex() = }")
            auth.verify(plain[12:])
            if plain[0] == 0 and plain[1] == prover_device_type:
                log.info("prover device type match")



# https://github.com/palmarci/OpenGuardian/blob/main/data/monitor_logs/g4s/2023_11_25_handshake_measurements.txt
g4s_key_raw = bytes.fromhex(
    "5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326"
)
g4s_keydb = KeyDatabase.from_bytes(g4s_key_raw)