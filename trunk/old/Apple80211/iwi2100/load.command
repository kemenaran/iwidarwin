#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
chown -R root:wheel build/Debug/iwi2100.kext
cp -rf build/Debug/iwi2100.kext /System/Library/Extensions
#kextunload iwi2100.kext
kextload /System/Library/Extensions/iwi2100.kext
