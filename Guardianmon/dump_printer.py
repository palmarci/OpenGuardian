import sys
import os
from enum import Enum
from datetime import datetime, timezone, timedelta
from binascii import hexlify
import re

# classes
class TerminalColors:
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKCYAN = '\033[96m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	RESET = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'

class BtMsg:
	class BtMsgType(Enum):
		READ = "<< READ"
		NOTIFY =  "<< NOTIFY"
		WRITE =  ">> WRITE"

	time : datetime
	type : BtMsgType
	service: str
	data: bytes
	decrypted: bool
	parsed: str
	comment: str = None

	def _dump(self):
		result = []

		if self.service == "sakeService" and dumpSake:
			result.append("...skipping sake dumps...")
		else:
			raw_part = f"{hexlify(self.data, ' ').decode()}"
			ascii_part = ''.join([chr(byte) if 32 <= byte < 127 else '.' for byte in self.data])
			dec_part = ' '.join(str(byte) for byte in self.data)
			result.append(f"raw: {raw_part}")
			result.append(f"dec: {dec_part}")
			result.append(f"ascii: {ascii_part}")
			if self.comment is not None:
				result.append("\n\n\n" + TerminalColors.OKCYAN + "\t" * 5 + "Comment: " + self.comment + TerminalColors.RESET + "\n\n")
			
		return result

	def __init__(self, time, type:str, service:str, data:str, decrypted, comment:str=None):
		self.time = time
		parsed_type = None
		self.decrypted = decrypted
		if comment != None:
			self.comment = comment.strip(" ")
		for t in self.BtMsgType:
			if type.upper() == t.name:
				parsed_type = t
		if not parsed_type:
			raise Exception(f"Could not parse type '{type}'")
		self.type = parsed_type

		if service.lower() in SERVICE_MAP:
			self.service = SERVICE_MAP[service]
		else:
			self.service = service
		self.data = bytearray.fromhex(data)

	def __lt__(self, other):
		return self.time < other.time
	
	def __str__(self, ):
		# i hope no one has to touch this ever again, this is terrible lol
		textcolor = ""
		if self.decrypted:
			textcolor = TerminalColors.OKGREEN 
		else:
			textcolor = TerminalColors.FAIL
		dumps = self._dump()

		time = self.time.strftime('%H:%M:%S')
		output = f"{time: <{8}} | "
		output += f"{self.type.value: <{10}} | "
		output += f"{self.service: <{50}}"
		offset = len(output)
		output += textcolor
		start_from_newline = False
		for dump in dumps:
			dumpList = [dump[i:i + dump_length] for i in range(0, len(dump), dump_length)]
			if start_from_newline:
				output += (offset) * " " 
			output += dumpList[0] + "\n"
			start_from_newline = True
			dumpList.pop(0)
			for i in dumpList:
				output += (offset) * " " + i + "\n"
		output += TerminalColors.RESET
		return output

# globals
dump_length = 100
filename = None
dumpSake = False
SERVICE_MAP = {
	"0000181f-0000-1000-8000-00805f9b34fb": "cgmService",
	"00002a52-0000-1000-8000-00805f9b34fb": "cgm_recordAccessControlPoint",
	"00002aa7-0000-1000-8000-00805f9b34fb": "cgm_measurement",
	"00002aa8-0000-1000-8000-00805f9b34fb": "cgm_feature",
	"00002aaa-0000-1000-8000-00805f9b34fb": "cgm_sessionStartTime",
	"00002aab-0000-1000-8000-00805f9b34fb": "cgm_sessionRunTime",
	"00002aac-0000-1000-8000-00805f9b34fb": "cgm_specificOperationControlPoint",

	"00000200-0000-1000-0000-009132591325": "cgm_MdtExtService",
	"00000201-0000-1000-0000-009132591325": "cgm_MdtExt_sensorConnectedState",
	"00000202-0000-1000-0000-009132591325": "cgm_MdtExt_sensorExpirationTime",
	"00000203-0000-1000-0000-009132591325": "cgm_MdtExt_sensorCalibartionTime",
	"00000204-0000-1000-0000-009132591325": "cgm_MdtExt_calibrationTimeRecommended",
	"00000205-0000-1000-0000-009132591325": "cgm_MdtExt_algorithmData",


	"0000180a-0000-1000-8000-00805f9b34fb": "deviceInfoService",
	"00002a19-0000-1000-8000-00805f9b34fb": "deviceInfo_chargeState",
	"00002a24-0000-1000-8000-00805f9b34fb": "deviceInfo_modelNumber",
	"00002a26-0000-1000-8000-00805f9b34fb": "deviceInfo_firmwareRevision",
	"00002a27-0000-1000-8000-00805f9b34fb": "deviceInfo_hardwareRevision",
	"00002a28-0000-1000-8000-00805f9b34fb": "deviceInfo_softwareRevision",
	"00002a50-0000-1000-8000-00805f9b34fb": "deviceInfo_pnpId", # some kind of version
	"00002a29-0000-1000-8000-00805f9b34fb": "deviceInfo_manufacturerName",

	"500d8e40-be34-11e4-9b24-0002a5d5c51b": "connectionManagement_clientRequestedParams",
	"5f0b2420-be34-11e4-bc62-0002a5d5c51b": "connectionManagement_activeParams",

	# these are the services which have only one port
	"0000fe82-0000-1000-0000-009132591325": "sakeService", 
	"0000180f-0000-1000-8000-00805f9b34fb": "batteryLevelService",


}

# helpers
def convert_timestamp(unix_timestamp):
	unix_timestamp = int(unix_timestamp) / 1000
	utc_datetime = datetime.fromtimestamp(unix_timestamp).replace(tzinfo=timezone.utc)
	tz = timezone(timedelta(hours=1))
	return utc_datetime.astimezone(tz)

def main():
	if len(sys.argv) > 1:
		filename = sys.argv[1]
	else:
		raise Exception("No file was given in the arguments")

	if not os.path.isfile(filename):
		raise FileNotFoundError(f"File not found: {filename}")

	lines = None
	with open(filename, "r") as f:
		lines = f.readlines()
	
	# fix newlines
	lines = [line.rstrip('\n') for line in lines]
	
	messages = []
	crypto_pairs = {}

	# extract the encrypted messages
	for line in lines:
		line = re.sub(r'\#.*', "", line) # ignore comments
		line = line.replace(" ", "")
		timestamp, module, hook, params = line.split(',')
		if module == "sake":
			d1, d2 = params.split(';')
			if hook == "encrypt":
				crypto_pairs[d2] = d1
			if hook == "decrypt":
				crypto_pairs[d1] = d2

	# parse the bt messages
	for line in lines:
		split = line.split("#")
		comment = None
		if len(split) == 2:
			line = split[0]
			comment = split[1]
		elif len(split) > 2:
			raise Exception(f"Invalid number of comments found on line: {line}")
		timestamp, module, hook, params = line.split(',')
		time = convert_timestamp(timestamp)
		if module == "bt":
			service, data = params.split(';')
			# try to get decrypted data
			bt_data = None
			decrypted = False
			if data in crypto_pairs:
				bt_data = crypto_pairs[data]
				decrypted = True
			else:
				bt_data = data
			# create msg
			msg = BtMsg(time, hook, service, bt_data, decrypted, comment)
			messages.append(msg)

	messages.sort()
	for m in messages:
		print(m)

if __name__ == "__main__":
	print("Use the Java project for decoding!")
	main()