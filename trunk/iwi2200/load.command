#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo chown -R root:wheel build/Debug/iwi2200.kext
sudo cp -rf build/Debug/iwi2200.kext /System/Library/Extensions
#sudo kextunload iwi2200.kext
sudo kextload /System/Library/Extensions/iwi2200.kext
