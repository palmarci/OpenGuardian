import argparse
import os
import tempfile
import zipfile
import shutil
from tqdm import tqdm
import sys
import hashlib

from keydb_scan import scan_folder

JADX_PATH = r"/home/marci/tools/jadx-1.5.3/bin/jadx"

def sha256sum(filename):
    with open(filename, 'rb', buffering=0) as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()

# jadx has native support omg!

# def is_xapk(file_path):
#     return file_path.lower().endswith('.xapk')

# def find_apk_in_xapk(xapk_path, temp_dir, pkg_name):
#     try:
#         with zipfile.ZipFile(xapk_path, 'r') as z:
#             apk_name = pkg_name + ".apk" # base apk
#             z.extract(apk_name, temp_dir) # unzip it
#             ver = xapk_path.split("_")[-1].replace(".xapk", "") # extract version
#             extracted_path_final = os.path.join(temp_dir, pkg_name + "_" + ver + ".apk")
#             shutil.move(os.path.join(temp_dir, apk_name), extracted_path_final)
#             return extracted_path_final
#     except zipfile.BadZipFile:
#         print(f"Warning: Bad XAPK file '{xapk_path}'")
#         return None

def process_apk(apk_path):

    matched_folder = "matches"
    if not os.path.isdir(matched_folder):
        os.mkdir(matched_folder)

    temp_name = "temp"
    if os.path.isdir(temp_name):
        shutil.rmtree(temp_name)
    os.mkdir("temp")
    os.system(f"{JADX_PATH} -j 14 -d {temp_name} -e {apk_path}")

    
    matches = scan_folder(temp_name)
    if len(matches) > 0:
        for m in matches:
            hash = sha256sum(m)
            out = os.path.join(matched_folder, hash)
            if not os.path.isfile(out):
                shutil.copy(m, out)
            else:
                print(f"WARNING: duped file hash for {hash}")
            print(f"{apk_path} matched {hash}")
            


def main():
    parser = argparse.ArgumentParser(description="Scan folders starting with 'com' and process APK/XAPK files.")
    parser.add_argument("folder", help="Root folder to scan")
    args = parser.parse_args()

    # First, build a list of all files to process
    all_files = []

    for root, dirs, files in os.walk(args.folder):
        if not os.path.basename(root).startswith("com"):
            continue
        pkg_name = os.path.basename(root)
        for file_name in files:
            file_path = os.path.join(root, file_name)
            all_files.append((file_path, pkg_name))

    # Now iterate with tqdm over the complete list
    for file_path, pkg_name in tqdm(all_files, desc="Processing APK/XAPK files"):
        # your processing logic here
        #pass

            #temp_dir = None

            # if is_xapk(file_path):
            #     temp_dir = tempfile.mkdtemp()
            #     apk_path = find_apk_in_xapk(file_path, temp_dir, pkg_name)
            #     if apk_path is None:
            #         shutil.rmtree(temp_dir)
            #         continue
            # elif file_path.lower().endswith('.apk'):
            #     apk_path = file_path
            # else:
            #     continue  # Skip non-APK/XAPK files

            if not (file_path.endswith(".xapk") or file_path.endswith(".apk")):
                continue

            process_apk(file_path)

            # try:
            #     if process_apk(file_path):
            #         if temp_dir:
            #             shutil.rmtree(temp_dir)
            # except Exception as e:
            #     print(f"Error processing '{file_path}': {e}")
            #     if temp_dir:
            #         shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
