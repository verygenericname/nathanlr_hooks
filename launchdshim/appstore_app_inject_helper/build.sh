#!/bin/bash

set -e

rm appstorehelper.dylib | true
xcrun -sdk iphoneos clang *.c ../bundlehooks/*.c -o appstorehelper.dylib -arch arm64 -dynamiclib -miphoneos-version-min=16.0 -Os -Wno-deprecated-declarations -I../bundlehooks/
#install_name_tool -change /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate /var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate appstorehelper.dylib
#install_name_tool -add_rpath /var/jb/usr/lib appstorehelper.dylib
ldid -S appstorehelper.dylib
~/building/ChOma/output/tests/ct_bypass -i appstorehelper.dylib -o appstorehelper.dylib -r
