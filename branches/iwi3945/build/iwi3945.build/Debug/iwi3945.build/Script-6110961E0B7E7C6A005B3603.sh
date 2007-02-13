#!/bin/sh
cd /private/var/root/svn/branches/iwi3945
#cd $SRCROOT

chown -R root:wheel build/Debug/iwi2100.kext

rm -rf /System/Library/Extensions/iwi3945.kext

# cp -rf build/Debug/iwi3945.kext /System/Library/Extensions

rm -rf /private/var/root/iwi3945.pkg

# build only if no .dmg exists
if [ -e /private/var/root/iwi3945.dmg ] ; then
	exit 0
fi

rm -f /private/var/root/iwi3945.dmg

/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -build -p /private/var/root/iwi3945.pkg -proj iwi3945.pmproj

hdiutil create -format UDZO -srcfolder /private/var/root/iwi3945.pkg /private/var/root/iwi3945.dmg

sleep 1

rm -rf /private/var/root/iwi3945.pkg

