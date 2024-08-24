#!/bin/bash
set -e
rm libTS2JailbreakEnv.dylib | true
xcrun -sdk iphoneos clang *.m ../launchdshim/fishhook/fishhook.c -o libTS2JailbreakEnv.dylib -dynamiclib -Wno-int-conversion -Wno-incompatible-function-pointer-types -miphoneos-version-min=16.0 -framework Foundation -I../launchdshim/fishhook/
ldid -S libTS2JailbreakEnv.dylib
~/building/TrollStore/Exploits/fastPathSign/fastPathSign libTS2JailbreakEnv.dylib
