#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo chown -R root:wheel build/Debug/iwi3945.kext
sudo cp -rf build/Debug/iwi3945.kext /System/Library/Extensions
#sudo kextunload iwi3945.kext
sudo kextload /System/Library/Extensions/iwi3945.kext
