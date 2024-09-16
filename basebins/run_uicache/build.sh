#!/bin/bash

set -e

xcrun -sdk iphoneos clang run_uicache.m -o run_uicache -arch arm64 -miphoneos-version-min=16.0 -Os
ldid -Sent.xml run_uicache -Icom.nathan.uicache
~/building/TrollStore/Exploits/fastPathSign/fastPathSign run_uicache
