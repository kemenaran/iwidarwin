#!/bin/sh
exit 0

#cd /private/var/root/svn/trunk/iwi3945
#cd "$SRCROOT"

sudo chown -R root:wheel build/Debug/iwi3945.kext

#rm -rf /System/Library/Extensions/iwi3945.kext

cp -rf build/Debug/iwi3945.kext /System/Library/Extensions

rm -rf iwi3945.pkg

# build only if no .dmg exists
if [ -e iwi3945.dmg ] ; then
	exit 0
fi

rm -f iwi3945.dmg

/Developer/Applications/Utilities/PackageMaker.app/Contents/MacOS/PackageMaker -build -p iwi3945.pkg -proj iwi3945.pmproj

hdiutil create -format UDZO -srcfolder iwi3945.pkg iwi3945.dmg

sleep 1

rm -rf iwi3945.pkg

