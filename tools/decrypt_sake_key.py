from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
from binascii import hexlify

def decrypt_cbc_aes(key, data):
    key_bytes = base64.b64decode(key)
    iv = bytes([0] * 16)  # Assuming IV is all zeros as in the Java code
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    encrypted_data = base64.b64decode(data)
    decrypted_data = cipher.decrypt(encrypted_data)
    print(hexlify(decrypted_data))
    return decrypted_data #.decode('ISO-8859-1')  # Java's StandardCharsets.ISO_8859_1

# Example usage:
key = "jDr6VD7W47UEhHYjjIIE0Eayd81TAs16sOECfHjxaCY="
data = "Ix6EzqqJ3p8oBqSb+jIEzrb8c1iz1Hu15TE21agYzpAUheqZ2JenLqGtBrhtezPLaupKRmHXoJdqtqaHnlaxiubUdKdJGdsRUOS65VQfV3HOAqhpDctrOnd6/islVn8Qp+xy8IjOAkFssIHykebMig=="

decrypted_data = decrypt_cbc_aes(key, data)
print(decrypted_data)