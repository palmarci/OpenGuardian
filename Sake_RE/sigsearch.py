import struct
from common import TMP_ELF

class ByteSignature:
	def __init__(self, signature):
		self.bytes, self.mask = self.parse_signature(signature)

	def parse_signature(self, signature):
		# Remove all whitespaces
		signature = signature.replace(" ", "")
		
		if not signature:
			raise ValueError("Signature cannot be empty")

		bytes_list = []
		mask_list = []
		
		i = 0
		while i < len(signature):
			if signature[i] == "?":
				bytes_list.append(None)  # Wildcard byte
				mask_list.append(0)      # Wildcard mask
				i += 1
			else:
				byte = int(signature[i:i+2], 16)
				bytes_list.append(byte)
				mask_list.append(1)
				i += 2
		
		return bytes_list, mask_list

	def get_bytes(self):
		return self.bytes

	def get_mask(self):
		return self.mask


def find_signature(signature):
	byte_signature = ByteSignature(signature)
	signature_bytes = byte_signature.get_bytes()
	signature_mask = byte_signature.get_mask()

	with open(TMP_ELF, "rb") as f:
		data = f.read()

	signature_len = len(signature_bytes)
	for i in range(len(data) - signature_len + 1):
		match = True
		for j in range(signature_len):
			if signature_mask[j] == 1: 
				if data[i + j] != signature_bytes[j]:
					match = False
					break
		if match:
			print(f"found sig {hex(i)}")
			return i 

	print("WARNING! no sig addr found!")
	return None 

if __name__ == "__main__":
	signature = "F0 B5 03 AF 2D E9 00 0B C8 B0 06 46 1A 48 00 2E 78 44 04 68 20 68 47 90 4F F0 00 00 ? ? 0D 46"
	offset = find_signature("/tmp/dump.bin", signature)
	start, end = resolve_map()
	if offset is not None:
		print(f"Signature found at offset: {hex(offset+start)}")
	else:
		print("Signature not found.")
