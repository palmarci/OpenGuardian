import base64
import json
import os
import xml.etree.ElementTree as ET
from io import BytesIO

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# USAGE:
# download frida
# copy frida server to your phone
# start the frida server
# start the app on your phone
# run the command: frida -U -p (adb shell pidof com.medtronic.diabetes.minimedmobile.eu) -l dump-medtronic-aks.js -o keys.json
# type "exit" in frida cli to write the output file and exit
# get StorageSecureRepository.xml:
# adb shell
# su -
# cp /data/data/com.medtronic.diabetes.minimedmobile.eu/shared_prefs/StorageSecureRepository.xml /sdcard
# exit
# adb pull /sdcard/StorageSecureRepository.xml .


db_dir = os.path.join(os.getcwd(), "db")
os.chdir(db_dir)

key_file = "keys.json"
ssr_file = "StorageSecureRepository.xml"

def read_repos(file_path):
	tree = ET.parse(file_path)
	root = tree.getroot()

	db_records = [] 

	for string_elem in root.findall(".//string"):
		name = string_elem.get("name")
		value = string_elem.text
		#print(f"Name: {name}, Value: {value}")
		value = base64.b64decode(value.strip())
		db_records.append({"name": name, "value": value})
	
	return db_records

def read_key_file(path):
	data = None
	data = open(key_file, "r").read()
	data = data.splitlines()
	keys = []
	for i in data:
		if i != "null":
			keys.append(json.loads(i))
	return keys
	
def decrypt_with_keystore(encrypted_data, private_key):
	if encrypted_data is None:
		return None

#	try:
	# Load the private key
	private_key = serialization.load_pem_private_key(private_key, password=None)

	# Decrypt the data
	decrypted_data = private_key.decrypt(encrypted_data, padding.PKCS1v15())

	# Convert bytes to a string using UTF-8 encoding
	return decrypted_data.decode('utf-8')
	#except Exception as e:
	#	return encrypted_data


def main():
	if not os.path.isfile(key_file):
		raise Exception("Key file does not exist on disk")

	if not os.path.isfile(ssr_file):
		raise Exception("SSR file does not exist on disk")

	keys = read_key_file(key_file)
	repos = read_repos(ssr_file)

	target = "DATABASE_KEY"
	for repo in repos:
		if repo["name"] == target:
			for key in keys:
				if key["mAlias"] == "USRPKEY_" + target:
					modulus_bytes = key["mModulus"].to_bytes((key["mModulus"].bit_length() + 7) // 8, 'big')
					pem_format = f"-----BEGIN RSA PRIVATE KEY-----\n{base64.b64encode(modulus_bytes).decode()}\n-----END RSA PRIVATE KEY-----"
					pem_bytes = pem_format.encode()
					decrypt_with_keystore(repo["value"], pem_bytes)


main()



# app logs db key = 0C4s6yJaE5Lh1aiEhfLILepqetYk7/cQbEDXMdAa5Gs=
# ^ what is this??