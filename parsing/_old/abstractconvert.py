def and15(value):
	return value & 0x0F

def and255(value):
	return value & 0xFF

def bytes_to_uint16(b, b2):
	return and255(b) + (and255(b2) << 8)

def bytes_to_uint24(b, b2, b3):
	return and255(b) + (and255(b2) << 8) + (and255(b3) << 16)

def bytes_to_unsigned_int32(b, b2, b3, b4):
	return and255(b) + (and255(b2) << 8) + (and255(b3) << 16) + (and255(b4) << 24)

def sign_extend(value, bit_width):
	sign_bit = 1 << (bit_width - 1)
	return (value - (value & (sign_bit - 1))) * (-1) if (value & sign_bit) != 0 else value


def unpack_int(value:bytearray, i, length):

	and_15_result = and15(i) + length
	b_arr = value

	if and_15_result > len(b_arr):
		return None

	if i == 33:
		and_255_result = and255(b_arr[length])
		i3 = 8
	elif i == 34:
		and_255_result = bytes_to_uint16(b_arr[length], b_arr[length + 1])
		i3 = 16
	elif i != 36:
		if i == 17:
			temp = and255(b_arr[length])
		elif i == 18:
			temp = bytes_to_uint16(b_arr[length], b_arr[length + 1])
		elif i == 19:
			temp = bytes_to_uint24(b_arr[length], b_arr[length + 1], b_arr[length + 2])
		elif i == 20:
			temp = bytes_to_unsigned_int32(b_arr[length], b_arr[length + 1], b_arr[length + 2], b_arr[length + 3])
		else:
			raise ValueError(f"FormatException({i})")
		return temp

	else:
		and_255_result = bytes_to_unsigned_int32(b_arr[length], b_arr[length + 1], b_arr[length + 2], b_arr[length + 3])
		i3 = 32

	temp = sign_extend(and_255_result, i3)
	if temp is None:
		raise Exception("Unpack exception")
	return temp

