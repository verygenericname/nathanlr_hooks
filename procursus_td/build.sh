#!/bin/bash
set -e
rm libTS2JailbreakEnv.dylib | true
xcrun -sdk iphoneos clang *.m ChOma/src/*.c ChOma/tests/ct_bypass/*.c ../launchdshim/fishhook/fishhook.c -o libTS2JailbreakEnv.dylib -dynamiclib -Wno-int-conversion -Wno-incompatible-function-pointer-types -miphoneos-version-min=16.0 -framework Foundation -I../launchdshim/fishhook/ -IChOma/ -LChOma/external/ios/ -lcrypto -O2
ldid -S libTS2JailbreakEnv.dylib
~/building/TrollStore/Exploits/fastPathSign/fastPathSign libTS2JailbreakEnv.dylib
