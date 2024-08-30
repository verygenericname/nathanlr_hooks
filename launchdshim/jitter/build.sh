set -e

rm jitterd | true
xcrun -sdk iphoneos clang *.c -o jitterd -arch arm64 -Wno-error -O3
ldid -Sent.plist jitterd -Icom.hrtowii.jitterd
~/building/ChOma/output/tests/ct_bypass -i jitterd -o jitterd -r
