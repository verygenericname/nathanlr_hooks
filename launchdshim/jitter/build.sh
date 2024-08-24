set -e

rm jitterd | true
xcrun -sdk iphoneos clang *.m -o jitterd -arch arm64 -fobjc-arc -isystem -Wno-error -O3
ldid -Sent.plist jitterd
~/building/ChOma/output/tests/ct_bypass -i jitterd -o jitterd -r
