apkSigner="/home/marci/Downloads/uber-apk-signer-1.2.1.jar"

if [[ ! -f AndroidManifest.xml ]] ; then
    echo 'you are not in a project folder'
    exit
fi


if ! test -f "$apkSigner"; then
  echo "Invalid path for the apk signer jar file. Edit this script!\n"
  exit 1
fi

mkdir -p dist
touch dist/asd.apk
rm -rf dist/*.apk && apktool b . && java -jar "$apkSigner" -apks dist/ && adb install dist/*Signed*.apk
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
/bin/bash "$SCRIPT_DIR/stop_and_clean.sh"