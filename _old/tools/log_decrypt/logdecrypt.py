import os
import sys
from binascii import hexlify
from io import BytesIO
import zlib
import json
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64decode, b64encode

AES_KEY_LENGTH = 256 // 8 # convert to bytes
INIT_VECTOR_SIZE = 12
AUTH_TAG_LENGTH = 16

### WARNING!!!! YOU NEED TO PATCH THE PUBLIC KEY IN THE APK FIRST!

class Decryptor:
	def __init__(self, private_rsa_key: RSAPrivateKey):
		self.private_rsa_key = private_rsa_key

	def decrypt_with_privkey(self, data):
		decrypted_data = self.private_rsa_key.decrypt(
			data,
			padding.OAEP(
				mgf=MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		return decrypted_data

	def __aes_nopadding_cipher(self, secret_key, init_vector, auth_tag):
		cipher = Cipher(algorithms.AES(secret_key), modes.GCM(init_vector, tag=auth_tag))
		return cipher.decryptor()

	def decrypt(self, raw_encrypted_data):

		if raw_encrypted_data[AES_KEY_LENGTH * 8] != INIT_VECTOR_SIZE:
			raise Exception(f"Could not find {hex(INIT_VECTOR_SIZE)} at byte {AES_KEY_LENGTH * 8}")
	
		encrypted_aes_data = raw_encrypted_data[0:AES_KEY_LENGTH * 8]
		init_vector_start = AES_KEY_LENGTH * 8 + 1
		init_vector_end = init_vector_start + INIT_VECTOR_SIZE
		init_vector = raw_encrypted_data[init_vector_start:init_vector_end]
		aes_data = raw_encrypted_data[init_vector_end:-AUTH_TAG_LENGTH]
		auth_tag = raw_encrypted_data[-AUTH_TAG_LENGTH:]

		aes_key = self.decrypt_with_privkey(encrypted_aes_data)
		aes_cipher = self.__aes_nopadding_cipher(aes_key, init_vector, auth_tag=auth_tag)
		decrypted_data = aes_cipher.update(aes_data) + aes_cipher.finalize()
		return decrypted_data
	
class Encryptor:

	def __init__(self, public_key: RSAPublicKey):
		self.public_key = public_key

	def __encrypt_with_pubkey(self, data):
		encrypted_data = self.public_key.encrypt(
			data,
			padding.OAEP(
				mgf=MGF1(algorithm=hashes.SHA256()),
				algorithm=hashes.SHA256(),
				label=None
			)
		)
		return encrypted_data
	
	def __aes_nopadding_cipher(self, secret_key, init_vector):
		cipher = Cipher(algorithms.AES(secret_key), modes.GCM(init_vector))
		return cipher.encryptor()

	def encrypt(self, data:bytes):
		aes_key = os.urandom(AES_KEY_LENGTH)  # Generate a random 256-bit AES key
		init_vector = os.urandom(INIT_VECTOR_SIZE)  # Generate a random 96-bit initialization vector (IV)
		aes_cipher = self.__aes_nopadding_cipher(aes_key, init_vector)
		aes_encrypted_data = aes_cipher.update(data) + aes_cipher.finalize()
		pubkey_encrypted_data = self.__encrypt_with_pubkey(aes_key)
		combined_data = pubkey_encrypted_data + bytes([INIT_VECTOR_SIZE]) + init_vector + aes_encrypted_data
		return combined_data, aes_cipher.tag

def load_private_key(private_key_path, password:str):
	with open(private_key_path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(key_file.read(), password=password.encode())
	return private_key

def load_public_key(public_key_path):
	with open(public_key_path, "rb") as key_file:
		public_key = serialization.load_pem_public_key(key_file.read())
	return public_key

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('file')
	args = parser.parse_args()
	
	if os.path.isfile(args.file):
		input_path = os.path.realpath(args.file)
	else:
		raise FileNotFoundError

	parent_folder = os.path.dirname(__file__)
	os.chdir(parent_folder)
	
	private_key = load_private_key("keys/private.pem", password="1234")
	public_key = load_public_key("keys/public.pem")
	output_filename = input_path.replace(".exp", ".decrypted")

	enc = Encryptor(public_key)
	dec = Decryptor(private_key)

	data = open(input_path, "r").read()
	data = json.loads(data)
	decoded_data = b64decode(data["payload"]["data"])

	decrypted_data = dec.decrypt(decoded_data)
	print(f"decryption successful!")
	decompressed_data = zlib.decompress(decrypted_data)
	print(f'decompression ok')
	open(output_filename, "wb").write(decompressed_data)
	print(f"wrote file {output_filename}")

if __name__ == "__main__":
	main()