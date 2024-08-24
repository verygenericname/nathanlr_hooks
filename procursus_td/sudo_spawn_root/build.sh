#!/bin/bash

set -e

rm sudo_spawn_root | true
xcrun -sdk iphoneos clang sudo_spawn_root.c -o sudo_spawn_root -arch arm64
ldid -Sent.xml sudo_spawn_root
~/building/TrollStore/Exploits/fastPathSign/fastPathSign sudo_spawn_root
