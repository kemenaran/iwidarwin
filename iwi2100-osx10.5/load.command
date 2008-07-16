#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo cp -rf build/Debug/iwi2100.kext /System/Library/Extensions
sudo chown -R root:wheel /System/Library/Extensions/iwi2100.kext
kextunload /System/Library/Extensions/iwi2100.kext
rm /System/library/Extensions.*
kextload /System/Library/Extensions/iwi2100.kext
