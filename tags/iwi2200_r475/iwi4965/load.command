#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
sudo cd "$LOCPATH"
sudo chown -R root:wheel build/Debug/iwi4965.kext
sudo cp -rf build/Debug/iwi4965.kext /System/Library/Extensions
sudo kextunload iwi4965.kext
sudo kextload /System/Library/Extensions/iwi4965.kext
