from abstractconvert import unpack_int, and15


payload = None

def connectionActiveParamsUnpack(payload):
	update_source = unpack_int(payload, 17, 0)
	and15_1 = (17 & 15) + 0
	connection_interval = unpack_int(payload, 18, and15_1)
	and15_2 = and15_1 + (18 & 15)
	slave_latency = unpack_int(payload, 18, and15_2)
	and15_3 = and15_2 + (18 & 15)
	connectionSupervisionTimeOut = unpack_int(payload, 18, and15_3)
	#TODO checksum
	return f"update_source: {update_source}, connection_interval:{connection_interval},slave_latency: {slave_latency}, connectionSupervisionTimeOut: {connectionSupervisionTimeOut}"