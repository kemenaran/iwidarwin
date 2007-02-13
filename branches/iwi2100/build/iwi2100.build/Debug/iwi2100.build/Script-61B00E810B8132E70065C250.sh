#!/bin/sh
cd /private/var/root/svn/branches/iwi2100
#cd "$SRCROOT"

chown -R root:wheel build/Debug/iwi2100.kext

rm -rf /System/Library/Extensions/iwi2100.kext

# cp -rf build/Debug/iwi2200.kext /System/Library/Extensions

rm -rf /private/var/root/iwi2100.pkg

# build only if no .dmg exists
if [ -e /private/var/root/iwi2100.dmg ] ; then
	exit 0
fi

rm -f /private/var/root/iwi2100.dmg

/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -build -p /private/var/root/iwi2100.pkg -proj iwi2100.pmproj

hdiutil create -format UDZO -srcfolder /private/var/root/iwi2100.pkg /private/var/root/iwi2100.dmg

sleep 1

rm -rf /private/var/root/iwi2100.pkg

