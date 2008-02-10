#/bin/sh

LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
kextunload build/Debug/iwi3945-loadable.kext
rm -rf build/Debug/iwi3945-loadable.kext
chown -R root:wheel build/Debug/iwi3945.kext
chmod -R 755 build/Debug/iwi3945.kext
mv build/Debug/iwi3945.kext build/Debug/iwi3945-loadable.kext
sync
kextload build/Debug/iwi3945-loadable.kext
