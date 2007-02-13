#!/bin/sh
cd /private/var/root/svn/branches/iwi2200-0.7
#cd "$SRCROOT"

chown -R root:wheel build/Debug/iwi2200.kext

rm -rf /System/Library/Extensions/iwi2200.kext

cp -rf build/Debug/iwi2200.kext /System/Library/Extensions

rm -rf /private/var/root/iwi2200.pkg

# build only if no .dmg exists
if [ -e /private/var/root/iwi2200.dmg ] ; then
	exit 0
fi

rm -f /private/var/root/iwi2200.dmg

/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -build -p /private/var/root/iwi2200.pkg -proj iwi2200.pmproj

hdiutil create -format UDZO -srcfolder /private/var/root/iwi2200.pkg /private/var/root/iwi2200.dmg

sleep 1

rm -rf /private/var/root/iwi2200.pkg

