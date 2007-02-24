#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
chown -R root:wheel build/Debug/iwi2200.kext
cp -rf build/Debug/iwi2200.kext /System/Library/Extensions
#kextunload iwi2200.kext
kextload /System/Library/Extensions/iwi2200.kext
