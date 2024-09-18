#!/bin/bash

set -e

rm generalhook.dylib | true
xcrun -sdk iphoneos clang *.m ../bundlehooks/*.m  -o generalhook.dylib -arch arm64 -I../bundlehooks/ -dynamiclib -miphoneos-version-min=16.0 -framework Foundation -Os -Wno-deprecated-declarations -I/Users/nathan/theos/vendor/include -I../litehook/ -L/Users/nathan/theos/vendor/lib -lsubstrate # ../litehook/litehook.c -I../litehook/external/include/
install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /System/Library/VideoCodecs/lib/libellekit.dylib generalhook.dylib
install_name_tool -add_rpath /var/jb/usr/lib generalhook.dylib
ldid -S generalhook.dylib
~/building/ChOma/output/tests/ct_bypass -i generalhook.dylib -o generalhook.dylib -r
