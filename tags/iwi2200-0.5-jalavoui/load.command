#/bin/sh
cd /System/Library/Extensions
cp -rf /var/root/iwi2200/build/Debug/iwi2200.kext .
chown -R root:wheel iwi2200.kext
kextunload iwi2200.kext
kextload iwi2200.kext
