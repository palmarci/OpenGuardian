import requests
import json
from binascii import unhexlify

class SakeClient:
	def __init__(self, server_name: str):
		self.server_name = server_name

	def perform_action(self, action: str, request_data: bytes = None) -> str:
		print("--"*10)
		request_hex = "null"
		if request_data:
			request_hex = self.byte_array_to_hex_string(request_data)
		else:
			if action != "status":
				print(f"[sake] {action} warning: sending 'null' as request!")

		headers = {"Content-Type": "application/json"}
		payload = json.dumps({"action": action, "data": request_hex})

		try:
			response = requests.post(self.server_name, data=payload, headers=headers)
			print(payload)
			if response.status_code > 0:
				# Parse the response
				response_json = response.json()
				print(response_json)
				response_data = response_json.get("data", "<empty>")
				success_str = response_json.get("success")
				success = success_str == True
				log_msg = (f"[sake] {action} response: code={response.status_code}, "
						   f"success={success}, data={response_data}")
				print(log_msg)
				return response_data
			else:
				print(f"[sake] invalid response from server: {response.status_code}")
				return ""
		except Exception as e:
			print(f"[sake] error during {action}: {e}")
			return ""

	def sake_get_status(self) -> str:
		return self.perform_action("status")

	def sake_init(self, key_db: bytes) -> bool:
		response_data = self.perform_action("init", key_db)
		return response_data != ""

	def sake_close(self) -> bool:
		response_data = self.perform_action("close")
		return response_data != ""

	def sake_encrypt(self, data: bytes) -> bytes:
		response_data = self.perform_action("encrypt", data)
		return self.hex_string_to_byte_array(response_data)

	def sake_decrypt(self, data: bytes) -> bytes:
		response_data = self.perform_action("decrypt", data)
		return self.hex_string_to_byte_array(response_data)

	def sake_handshake(self, data: bytes) -> bytes:
		response_data = self.perform_action("handshake", data)
		return self.hex_string_to_byte_array(response_data) if response_data else b""

	def sake_get_last_error(self) -> str:
		return self.perform_action("get_error")


	# Helper functions
	def byte_array_to_hex_string(self, byte_array: bytes) -> str:
		return byte_array.hex()

	def hex_string_to_byte_array(self, hex_string: str) -> bytes:
		return bytes.fromhex(hex_string)

if __name__ == "__main__":
	sc = SakeClient("http://192.168.1.98:8080/")
	key = unhexlify("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326")
	#key = unhexlify("00")
	#print(sc.sake_get_status())
	print(sc.sake_init(key))
	#print(f"fos = {sc.sake_get_last_error()}")
	#print(sc.sake_get_status())
