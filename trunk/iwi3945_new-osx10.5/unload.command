#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo kextunload build/Debug/iwi3945.kext
sudo rm -Rf build/Debug/iwi3945.kext
sudo rm -Rf /Users/netwarrior/Desktop/test