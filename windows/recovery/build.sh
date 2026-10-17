#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
"${RCON_MINGW_CXX:-x86_64-w64-mingw32-g++-posix}" -std=c++17 -O2 -Wall -Wextra -Wno-misleading-indentation \
  -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0602 -shared -static \
  -Wl,--dynamicbase,--nxcompat -o rcon-recovery.dll provider.cpp \
  -lole32 -lshlwapi -luuid -lsecur32 -lwtsapi32 -ladvapi32
