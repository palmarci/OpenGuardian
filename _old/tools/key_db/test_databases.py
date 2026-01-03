from binascii import hexlify, unhexlify
from crc import check_crc
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import InvalidUnwrap
import base64

def base64_decode_urlsafe(data: str) -> bytes:
	data = data.replace('-', '+').replace('_', '/')
	padding_needed = len(data) % 4
	if padding_needed:
		data += '=' * (4 - padding_needed)
	return base64.b64decode(data)

def decrypt_safe(key_base64:str, encrypted_base64:str):
	key = base64_decode_urlsafe(key_base64)
	encrypted_data = base64.b64decode(encrypted_base64)
	iv = bytes([0] * 16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	decryptor = cipher.decryptor()
	decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
	return decrypted_data

def decrypt_raw(key:str, data:str):
	key_bytes = base64.b64decode(key)
	iv = bytes([0] * 16)
	cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
	encrypted_data = base64.b64decode(data)
	decrypted_data = cipher.decrypt(encrypted_data)
	return decrypted_data

# these are all shit i think
to_decrypt = [
	["B6ShRze1gZD46iooQZ6Nc9JvnHj_hbuWggRglwYqXLo", "72VzMzUIEBvOEemWVnSVWi6yYsWRXy2hMR+N5GI/hCLWh0ht/65YsF7X5xv7Ei2bqlaUEfya90rHk7WRIVQZdy7HSPXgtBkAPOnNvs7TKzR6UjZZAbxkm1uwmDMyX/aPvtXyM2vpYD+AnTnObVyCWA=="],
	["p5fFLr_n5lLPXx10WT9JPtv_BI4HtZTdLIR7qWYXv5s", "aWinAwAcY0tmqxcvgvNLMpYh/371K1F7aXFp223zYEmUC2HrfLAejVMzM5tF1wzwCsQKQj0Gk9t+JF31qq36Zw8/k0759FxJQVDDN2dwTt56PhbZSsz1a2THfUGSlSK6mAhN7b8pmFelXq3kdE0UnA=="],
	["6GVvstBZ43Ytb0nvXhkbloIQLD5BnCQPzYcfu18MJw0", "ffQwvuE5Pp4K3rRxiiBv72+Ng2m2Iy1D7vtWoKVtagSLfb7PfxXSLhBsgm7t/6nUcjOQ4LqpM9FvL4lNXY2sjK9OnqvAz0GuG80ScoFW5hNu9xfqsBYsOuE5h9V1ipZg17tc6CdUJlRBDUaB4Bu7bA=="], # this is with a modded apk
	["x13mylIDLIxr_Ejy9GZExCEyuBtHxjpdavvvHG8xYw=", "+dhkz2pM/DJmC6z63dy+fn0o3QMvz/EWzJw/vU0a4t8hQJO/sp1Pb87BKpqKQFbZif0VyXQ3UD80yrt5YzRkeMA1CHjIxVfgdn6KpCcGBOWXQMEX0y+u402Lg0yFn/n+9JakkeCFHX2t7lKhV29UAg=="], # original app 2.2.1
	["jDr6VD7W47UEhHYjjIIE0Eayd81TAs16sOECfHjxaCY=", "Ix6EzqqJ3p8oBqSb+jIEzrb8c1iz1Hu15TE21agYzpAUheqZ2JenLqGtBrhtezPLaupKRmHXoJdqtqaHnlaxiubUdKdJGdsRUOS65VQfV3HOAqhpDctrOnd6/islVn8Qp+xy8IjOAkFssIHykebMig=="],
	["JUFkunFXm7vyicOKQLA7omyMXVPuABIww7sncx082tw=", "7xVLkeGGtUVjj23LK5AkHtA5OdWsAYnLpmqIyX7h6yFhYcPildNAa0nwRjmCQCLyO6zwBRg2kx3elkuEVXx1IQkbwwj1aZNGF/g7Dol3eAmibYm5vao1a86Q7UOxEgTSTDBgYG6PlV88GQve5+sUVQ=="],
	["rQGQ5Xf3oaaTZKSg2z0VliYYI4MD9_nFKQtFVsFIGEo=", "e0WfGrRaEG/GwbkLl/pNEL1ILeyyrqdQ1f2T6YBcYt4bTTvjPaDLVqqRFmWvPicHmh6n8hPSkoLKpehYgCFdzwTN/mpoO8OKv/L+/hlXnU2NF0mHUPIMLEI1XS3IbwvJucGEzoMgdAzMx/mvcVuecw=="],
]

for i in range(0, len(to_decrypt)):
	print("*"*10)
	key, data = to_decrypt[i]

	try:
		raw = decrypt_raw(key, data)
		print(hexlify(raw))
		print(f"# {i} raw valid? {check_crc(raw)}")
	except Exception as e:
		print(f"# {i} decrypt_raw failed: {e}")

	try:
		safe = decrypt_safe(key, data)
		print(hexlify(safe))
		print(f"# {i} safe valid? {check_crc(safe)}")
	except Exception as e:
		print(f"# {i} decrypt_safe failed: {e}")

print("\n"*5)

maybe_keys = [
	"f75995e70401011bc1bf7cbf36fa1e2367d795ff09211903da6afbe986b650f14179c0e6852e0ce393781078ffc6f51919e2eaefbde69b8eca21e41ab59b881a0bea0286ea91dc7582a86a714e1737f558f0d66dc1895c",
	"5819c3a4c39ec3b6c383c2bf5ec3b44d61c39ac29620c3bc74c38bc2bdc39327c3a80cc296c39c5218c2a96c3f3425c3800ec38365316e70c3834002c2bd76c2b7c3b1c2813cc3a0c2a6514238c3b77d4dc29dc289c29a45c2bec2bf6dc2bac28dc29f1cc289c29e1ac2a664c3aac2ac37155bc3adc3a878c3b104c3ad21693e3320c398c3960ac28e41c28c492dc3ad7463c39bc282c386"
]

for i in maybe_keys:
	print(f"{i} valid? {check_crc(unhexlify(i))}")
