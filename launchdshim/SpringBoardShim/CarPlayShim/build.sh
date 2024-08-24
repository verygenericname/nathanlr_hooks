set -e

rm CarPlay | true
xcrun -sdk iphoneos clang *.m ../../litehook/litehook.c ../../bundlehooks/utils.m -o CarPlay -arch arm64 -miphoneos-version-min=16.0 -I../../litehook/ -I../../bundlehooks/ -fmodules -O3 -Wno-deprecated-declarations
#install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate CarPlay
#install_name_tool -add_rpath /var/jb/usr/lib CarPlay
ldid -Sent.plist CarPlay -Icom.apple.CarPlayApp
~/building/ChOma/output/tests/ct_bypass -i CarPlay -o CarPlay -r
