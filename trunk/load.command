#/bin/sh
cd /System/Library/Extensions
cp -rf /var/root/iwi3945/build/Debug/iwi3945.kext .
chown -R root:wheel iwi3945.kext
kextunload iwi3945.kext
kextload iwi3945.kext
