#!/bin/bash

set -e

rm launchdhook.dylib | true
xcrun -sdk iphoneos clang launchdhook.c ../fishhook/fishhook.c -o launchdhook.dylib -arch arm64 -miphoneos-version-min=16.0 -dynamiclib -I../fishhook/ -O2
ldid -S launchdhook.dylib
~/building/ChOma/output/tests/ct_bypass -i launchdhook.dylib -o launchdhook.dylib -r
