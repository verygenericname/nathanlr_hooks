set -e

rm cfprefsd | true
xcrun -sdk iphoneos clang *.m ../litehook/litehook.c -o cfprefsd -arch arm64 -miphoneos-version-min=16.0 -I../litehook/ -fmodules -O3 -Wno-deprecated-declarations
install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate cfprefsd
#install_name_tool -add_rpath /var/jb/usr/lib cfprefsd
ldid -Sent.plist cfprefsd -Icom.apple.cfprefsd
~/building/ChOma/output/tests/ct_bypass -i cfprefsd -o cfprefsd -r
