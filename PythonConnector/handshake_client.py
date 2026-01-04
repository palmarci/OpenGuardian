from __future__ import annotations

from typing import Optional
from binascii import hexlify
from secrets import token_bytes

from sake_crypto import Session, KeyDatabase, KEYDB_G4_CGM


class HandshakeClient:
    """Simple client-side wrapper around `Session` to drive the 0..5 handshake.

    Usage:
      hc = HandshakeClient(keydb_bytes=..., local_device_type=0x08)
      to_send = hc.handshake(server_msg_bytes)
      if to_send is not None: send it on the wire

    The wrapper keeps internal `Session` state and will return the proper
    client message (1_c or 3_c) when appropriate. You can seed the client's
    key material/nonce to reproduce captures or let them be generated.
    """

    def __init__(
        self,
        keydb:KeyDatabase,
        local_device_type: int = 0x08,
        client_key_material: Optional[bytes] = None,
        client_nonce: Optional[bytes] = None,
        client_message: Optional[bytes] = None,
    ):
        self.local_device_type = local_device_type
        self.session = Session()
        #if keydb_bytes is not None:
        self.session.client_key_database = keydb
        # pre-seed client material if provided
        if client_key_material is not None:
            if len(client_key_material) != 8:
                raise ValueError("client_key_material must be 8 bytes")
            self.session.client_key_material = client_key_material
        if client_nonce is not None:
            if len(client_nonce) != 4:
                raise ValueError("client_nonce must be 4 bytes")
            self.session.client_nonce = client_nonce
        # If a full 20-byte client message is given, we'll send it verbatim when asked
        self._client_message_override = client_message

    def build_handshake_1(self) -> bytes:
        """Construct a 20-byte client handshake_1 message.

        Format (as used by `handshake_1_c`):
          [0:8]   = client_key_material (8B)
          [8]     = client_device_type (1B)
          [9:13]  = client_nonce (4B)
          rest    = zeros (or kept from override)
        """
        if self._client_message_override is not None:
            cm = self._client_message_override
            if len(cm) != 20:
                raise ValueError("client_message override must be 20 bytes")
            # populate session fields so later steps (auth8) have the data
            self.session.client_key_material = cm[0:8]
            self.session.client_device_type = cm[8]
            self.session.client_nonce = cm[9:13]
            return cm

        if self.session.client_key_material is None:
            self.session.client_key_material = token_bytes(8)
        if self.session.client_nonce is None:
            self.session.client_nonce = token_bytes(4)

        msg = bytearray(20)
        msg[0:8] = self.session.client_key_material
        msg[8] = self.local_device_type
        msg[9:13] = self.session.client_nonce
        return bytes(msg)

    def handshake(self, data: bytes) -> Optional[bytes]:
        """Feed an incoming handshake message `data` (20 bytes) and return the
        client bytes to send (if any). The function automatically advances
        through the handshake steps.
        """
        if len(data) != 20:
            raise ValueError("handshake messages must be 20 bytes")

        # If we haven't seen the server advert yet, expect handshake_0_s
        if self.session.server_device_type is None:
            # process server advert
            self.session.handshake_0_s(data)
            # set local device type in session so key lookup works later
            self.session.client_device_type = self.local_device_type
            # build client handshake_1, populate session state as if it was sent
            msg1 = self.build_handshake_1()
            # update session as if client had sent this message (sets derivation/keys)
            self.session.handshake_1_c(msg1)
            return msg1

        # If server_key_material not set, this should be handshake_2 from server
        if self.session.server_key_material is None:
            # parse and validate handshake_2
            self.session.handshake_2_s(data)
            # after verifying handshake_2, compute handshake_3 reply
            return self.session.build_handshake_3_c()

        # If we've sent handshake_3 and now receive an encrypted server message
        # (handshake_4), call `handshake_4_s` which will initialize the crypt
        # contexts and validate the payload; then return handshake_5 reply.
        # This must be done even if crypt contexts are not yet present.
        if self.session.server_key_material is not None:
            # process server encrypted message (handshake_4)
            self.session.handshake_4_s(data)
            # build and return encrypted handshake_5 reply
            return self.session.build_handshake_5_c()

        # Other handshake messages (unexpected) -> no reply
        return None


if __name__ == "__main__":
  

    msg0 = bytes.fromhex("02015f0edcd0c2af98705bed6c8172856d860402")

    client_msg1 = bytes.fromhex("a579868377f401ae083405ef88cc0962d6079a04")
    msg2 = bytes.fromhex("77f3fb85b079310455fd8f47ddaf81ab49defc7b")

    hc = HandshakeClient(KEYDB_G4_CGM, local_device_type=0x08, client_message=client_msg1)

    out1 = hc.handshake(msg0)
    print("-> 1_c:", hexlify(out1).decode())

    out2 = hc.handshake(msg2)
    print("-> 3_c (generated, zero filler):", hexlify(out2).decode())

    # If you need the exact captured 3_c including the 12-byte filler, build it:
    filled_filler = bytes.fromhex("46cfaf03f9dbd4877d0a7d76")
    out2_filled = hc.session.build_handshake_3_c(filler=filled_filler)
    print("-> 3_c (with capture filler):", hexlify(out2_filled).decode())

    # Now feed server encrypted handshake_4 and get client's handshake_5 reply
    msg4 = bytes.fromhex("ef54ef03ad398363825fd434e69cd829630056fa")
    out3 = hc.handshake(msg4)
    print("-> 5_c:", hexlify(out3).decode())

    # compare to expected capture
    expected_5 = bytes.fromhex("2f22c383cf264fa4ebc5b10dc8a2c8a4b000619e")
    pad = 4
    expected_5 = expected_5[:-pad]
    out3 = out3[:-pad]
    print(f"{out3.hex()}\n{expected_5.hex()}")
    print("matches capture:", out3 == expected_5)