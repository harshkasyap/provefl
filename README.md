# provefl

To execute: g++ fedavg.cpp -o fedavg \
-I ../../../../vcpkg/installed/arm64-osx/include/SEAL-4.1 \
-I ../../../../vcpkg/installed/arm64-osx/include \
../../../../vcpkg/installed/arm64-osx/lib/libseal-4.1.a \
-lzstd -lz \
-L ../../../../vcpkg/installed/arm64-osx/lib \
-std=c++17 && ./fedavg
