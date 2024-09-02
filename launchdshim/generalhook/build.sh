#!/bin/bash

set -e

rm generalhook.dylib | true
xcrun -sdk iphoneos clang *.m ../bundlehooks/*.m  ../litehook/litehook.c -o generalhook.dylib -arch arm64 -I../litehook/ -I../bundlehooks/ -dynamiclib -miphoneos-version-min=16.0 -framework Foundation -O3 -Wno-deprecated-declarations -framework CoreTelephony
#install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate companionhook.dylib
#install_name_tool -add_rpath /var/jb/usr/lib companionhook.dylib
ldid -S generalhook.dylib
~/building/ChOma/output/tests/ct_bypass -i generalhook.dylib -o generalhook.dylib -r
