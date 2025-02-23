import base64
import binascii
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap

def base64_decode_urlsafe(data: str) -> bytes:
    """Decodes a Base64 URL-safe encoded string with no padding."""
    # Handle Base64 URL_SAFE by replacing URL safe chars and adding missing padding
    data = data.replace('-', '+').replace('_', '/')
    padding_needed = len(data) % 4
    if padding_needed:
        data += '=' * (4 - padding_needed)
    return base64.b64decode(data)

def decrypt_cbc_aes(key_base64, encrypted_base64):
    # Decode the base64 key and encrypted data with the proper format (URL_SAFE and NO_PADDING)
    key = base64_decode_urlsafe(key_base64)
    encrypted_data = base64.b64decode(encrypted_base64)  # Standard Base64 decode for encrypted data

    # Initialize the AES cipher with CBC mode and a zeroed IV (16-byte IV, all zeroes)
    iv = bytes([0] * 16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Perform the decryption
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Return the hexdump of the decrypted data
    return binascii.hexlify(decrypted_data).decode('utf-8')

# Example usage


data = [
    ["B6ShRze1gZD46iooQZ6Nc9JvnHj_hbuWggRglwYqXLo", "72VzMzUIEBvOEemWVnSVWi6yYsWRXy2hMR+N5GI/hCLWh0ht/65YsF7X5xv7Ei2bqlaUEfya90rHk7WRIVQZdy7HSPXgtBkAPOnNvs7TKzR6UjZZAbxkm1uwmDMyX/aPvtXyM2vpYD+AnTnObVyCWA=="],
    ["p5fFLr_n5lLPXx10WT9JPtv_BI4HtZTdLIR7qWYXv5s", "aWinAwAcY0tmqxcvgvNLMpYh/371K1F7aXFp223zYEmUC2HrfLAejVMzM5tF1wzwCsQKQj0Gk9t+JF31qq36Zw8/k0759FxJQVDDN2dwTt56PhbZSsz1a2THfUGSlSK6mAhN7b8pmFelXq3kdE0UnA=="],
    ["6GVvstBZ43Ytb0nvXhkbloIQLD5BnCQPzYcfu18MJw0", "ffQwvuE5Pp4K3rRxiiBv72+Ng2m2Iy1D7vtWoKVtagSLfb7PfxXSLhBsgm7t/6nUcjOQ4LqpM9FvL4lNXY2sjK9OnqvAz0GuG80ScoFW5hNu9xfqsBYsOuE5h9V1ipZg17tc6CdUJlRBDUaB4Bu7bA=="], # this is with a modded apk
    ["x13mylIDLIxr_Ejy9GZExCEyuBtHxjpdavvvHG8xYw=", "+dhkz2pM/DJmC6z63dy+fn0o3QMvz/EWzJw/vU0a4t8hQJO/sp1Pb87BKpqKQFbZif0VyXQ3UD80yrt5YzRkeMA1CHjIxVfgdn6KpCcGBOWXQMEX0y+u402Lg0yFn/n+9JakkeCFHX2t7lKhV29UAg=="] # original app 2.2.1
]


for d in data:
    out = decrypt_cbc_aes(d[0], d[1])
    print(out + "\n")