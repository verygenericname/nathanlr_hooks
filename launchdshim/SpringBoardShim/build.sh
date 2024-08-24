set -e

rm SpringBoard | true
xcrun -sdk iphoneos clang *.m ../litehook/litehook.c ../bundlehooks/utils.m -o SpringBoard -arch arm64 -miphoneos-version-min=16.0 -I../litehook/ -I../bundlehooks/ -fmodules -O3 -Wno-deprecated-declarations
#install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate SpringBoard
#install_name_tool -add_rpath /var/jb/usr/lib SpringBoard
ldid -Sent.plist SpringBoard -Icom.apple.springboard
~/building/ChOma/output/tests/ct_bypass -i SpringBoard -o SpringBoard -r
