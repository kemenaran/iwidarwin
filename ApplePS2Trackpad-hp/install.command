cd /var/root/svn/trunk/ApplePS2Trackpad-hp/build/Development
sudo chown -R root:wheel ApplePS2Trackpad.kext
kextunload /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Trackpad.kext
rm -rf /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Trackpad.kext/
cp -r ApplePS2Trackpad.kext /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/
kextunload /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Trackpad.kext
kextunload /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Keyboard.kext
kextunload /System/Library/Extensions/ApplePS2Controller.kext
kextload /System/Library/Extensions/ApplePS2Controller.kext
kextload /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Trackpad.kext
kextload /System/Library/Extensions/ApplePS2Controller.kext/Contents/PlugIns/ApplePS2Keyboard.kext
echo "Done!"
