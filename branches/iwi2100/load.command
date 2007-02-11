#/bin/sh
cd /System/Library/Extensions
cp -rf /var/root/iwi2100/build/Debug/iwi2100.kext .
chown -R root:wheel iwi2100.kext
kextunload iwi2100.kext
kextload iwi2100.kext
