#/bin/sh

LOCPATH=`/usr/bin/dirname "$0"`
cd "$LOCPATH"
sudo sync
sudo kextunload build/Debug/iwi4965-loadable.kext
sudo rm -rf build/Debug/iwi4965-loadable.kext
sudo chown -R root:wheel build/Debug/iwi4965.kext
sudo chmod -R 755 build/Debug/iwi4965.kext
sudo mv build/Debug/iwi4965.kext build/Debug/iwi3945-loadable.kext
cp build/Debug/iwi4965-loadable.kext/Contents/MacOS/iwi4965 /Users/netwarrior/Desktop/iwi_bin
sudo sync
sudo kextload -i build/Debug/iwi4965-loadable.kext 
