#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo chown -R root:wheel build/Debug/iwi3945.kext
sudo chmod -R 755 build/Debug/iwi3945.kext
sudo cp -R build/Debug/iwi3945.kext/Contents/MacOS/iwi3945 /Users/netwarrior/Desktop/test
sync
sudo kextload build/Debug/iwi3945.kext
sudo rm -Rf build/Debug/iwi3945.kext
