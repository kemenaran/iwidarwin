#/bin/sh
LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
chown -R root:wheel build/Debug/iwi3945.kext
cp -rf build/Debug/iwi3945.kext /System/Library/Extensions
#kextunload iwi3945.kext
kextload /System/Library/Extensions/iwi3945.kext
