import zlib
from binascii import unhexlify,hexlify

def find_crc(message):
	msg_len = len(message)
	crc_length = 4
	for start in range(msg_len - crc_length + 1):
		crc_candidate = message[start:start + crc_length]
		#print(f"crc_candidate = {hexlify(crc_candidate)}")
		message_without_crc = message[:start] + message[start + crc_length:]
		calculated_crc = zlib.crc32(message_without_crc)
		if calculated_crc == int.from_bytes(crc_candidate, byteorder='big'):
			print(f"message_without_crc = {hexlify(message_without_crc)}")
			print(f"crc = {hexlify(crc_candidate)}")

def check_crc(input:bytes) -> bool:
	pad = unhexlify("0b"*11)
	if input[-11:] == pad:
		print("pad matches, removing")
		input = input[:-11]
		print(f"after pad removing: {hexlify(input)}")
	input_crc = input[0:4]
	calculated_crc = zlib.crc32(input[4:])
	calculated_crc = int.to_bytes(calculated_crc, byteorder="big", length=4)
	return input_crc == calculated_crc

def calc_crc(input:bytes) -> bytes:
	calculated_crc = zlib.crc32(input)
	return calculated_crc.to_bytes(4, byteorder="big")

if __name__ == "__main__":
	keydb = unhexlify("5fe5928308010230f0b50df613f2e429c8c5e8713854add1a69b837235a3e974304d8055ccb397838b90823c73236d6a83dcc9db3a2a939ff16145ca4169ef93a7fa39b20962b05e57413bff8b3d61fce0dfef2c43b326")
	find_crc(keydb)

	keydb = bytearray(keydb)
	keydb = keydb[4:]
	count_index = 0

	print(f"check crc result = {check_crc(keydb)}")
	print(keydb)
	print(f"device count beore = {keydb[count_index]}")
	keydb[0] = 7
	print(f"device count after = {keydb[count_index]}")
	new_crc = calc_crc(bytes(keydb))
	print(f"new crc = {hexlify(new_crc)}")
	print(f"final modified keydb = {hexlify(new_crc + keydb)}")

