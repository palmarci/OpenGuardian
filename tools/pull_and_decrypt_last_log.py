import os
import shutil
import subprocess
from datetime import datetime

running_from = os.getcwd()
script_dir = os.path.dirname(os.path.realpath(__file__))
final_output_filename = "latest.decrypted"

def extract_datetime(filename):
	parts = filename.split('_')
	parts.pop(0)
	date_part = "_".join(parts)
	date_part = date_part.replace(".exp", "")
	return datetime.strptime(date_part, "%Y-%m-%d_%H-%M-%S")

def main():
	print("running from", running_from)

	# remove old files
	for filename in os.listdir(running_from):
		if filename.startswith("minimed-app_") and filename.endswith(".decrypted"):
			os.remove(os.path.join(running_from, filename))
	if os.path.isfile(final_output_filename):
		os.remove(final_output_filename)

	# create empty temp folder
	tmp_folder = "/tmp/logdecrypt_temp"
	shutil.rmtree(tmp_folder, ignore_errors=True)
	os.makedirs(tmp_folder)

	# Pull files from the device
	os.chdir(tmp_folder)
	subprocess.run(["adb", "pull", "/sdcard/Android/data/com.medtronic.diabetes.minimedmobile.eu/files/diagnostic logs/"])

	# Find the latest .exp file
	latest_file = None
	latest_datetime = datetime.min
	for root, dirs, files in os.walk(tmp_folder):
		for file in files:
			if file.endswith('.exp'):
				file_path = os.path.join(root, file)
				file_path = os.path.realpath(file_path)
				containing_dir = os.path.basename(os.path.dirname(file_path)) # wtf medtronic
				print(f"found file {file_path} -> {containing_dir}")
				file_datetime = extract_datetime(containing_dir)
				if file_datetime > latest_datetime:
					latest_datetime = file_datetime
					latest_file = file_path

	if latest_file:
		print("The latest .exp file is:", latest_file)
	else:
		print("No .exp files found.")
		exit(1)

	# Decrypt the latest file
	subprocess.run(["python", os.path.join(script_dir, "logdecrypt", "logdecrypt.py"), latest_file])

	# move file
	filename, _ = os.path.splitext(latest_file)
	decrypted_file = filename + ".decrypted"
	targetfile = os.path.join(running_from, final_output_filename)
	shutil.move(decrypted_file, targetfile)
	os.chdir(running_from)
	shutil.rmtree(tmp_folder)
	
	# open with sublime 
	os.system(f"subl '{targetfile}' &")

if __name__ == "__main__":
	main()
