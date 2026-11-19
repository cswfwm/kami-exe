#!/bin/sh
# Windows EXE 交叉编译（容器内 zig 自带 Windows libc，无需 mingw）
set -e
zig build-exe src/main.zig \
  -target x86_64-windows-gnu \
  -O ReleaseSmall \
  -femit-bin="../卡密工具-windows-x64.exe"
echo "生成：../卡密工具-windows-x64.exe"
