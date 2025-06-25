#!/bin/bash -eu
# Copyright 2024 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# Install required base packages
apt-get update
apt-get install -y build-essential cmake pkg-config git libjson-c-dev

# === Build third-party dependencies statically (libubox + libubus) ===
DEPS_DIR="$PWD/deps"
INSTALL_DIR="$DEPS_DIR/install"
mkdir -p "$DEPS_DIR"
cd "$DEPS_DIR"

# ---------- libubox ----------
if [ ! -d "libubox" ]; then
  git clone --depth 1 https://github.com/openwrt/libubox.git
fi
cd libubox
rm -rf tests || true
mkdir -p build && cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

# ---------- libubus ----------
if [ ! -d "ubus" ]; then
  git clone --depth 1 https://git.openwrt.org/project/ubus.git
fi
cd ubus
rm -rf tests || true
mkdir -p build && cd build
cmake .. \
  -DCMAKE_INSTALL_PREFIX="$INSTALL_DIR" \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DBUILD_LUA=OFF \
  -DBUILD_EXAMPLES=OFF \
  -DBUILD_TESTS=OFF \
  -DBUILD_STATIC=ON \
  -DBUILD_SHARED_LIBS=OFF
make -j$(nproc)
make install
cd "$DEPS_DIR"

cd "$SRC/oss-fuzz-auto"

# Export paths for pkg-config & compiler
export PKG_CONFIG_PATH="$INSTALL_DIR/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
: "${LDFLAGS:=}"
export CFLAGS="$CFLAGS -I$INSTALL_DIR/include -D_GNU_SOURCE -std=gnu99"
export LDFLAGS="$LDFLAGS -L$INSTALL_DIR/lib"

# Generate capabilities-names.h (required by jail/capabilities.c)
# Ensure script has Unix line endings
sed -i 's/\r$//' make_capabilities_h.sh
bash ./make_capabilities_h.sh "$CC" > capabilities-names.h

# === Compile procd sources required for parseOCI ===
# Build all jail/* and utils/utils.c as position-independent objects
OBJ_DIR="$PWD/obj"
mkdir -p "$OBJ_DIR"

# Compile jail sources (rename main in jail.c to avoid symbol clash)
for f in $(ls jail/*.c); do
  if [[ "$f" == "jail/jail.c" ]]; then
    $CC $CFLAGS -Dmain=procd_jail_main -c "$f" -o "$OBJ_DIR/$(basename $f .c).o"
  else
    $CC $CFLAGS -c "$f" -o "$OBJ_DIR/$(basename $f .c).o"
  fi
done

# Compile additional helpers from utils (exclude askfirst.c)
$CC $CFLAGS -c utils/utils.c -o "$OBJ_DIR/utils.o"

# === Compile the fuzzer ===
$CC $CFLAGS -c procd-fuzz.c -o "$OBJ_DIR/fuzzer.o"

# Link statically
$CC $CFLAGS $LIB_FUZZING_ENGINE \
  "$OBJ_DIR"/*.o \
  $LDFLAGS -static -lubus -lubox -ljson-c -pthread -o $OUT/procd_parseoci_fuzzer

# Seed corpus directory (empty – OSS-Fuzz will populate) 
mkdir -p $OUT/procd_parseoci_fuzzer_seed_corpus

echo "Build completed successfully!"
echo "Fuzzer binary: $OUT/procd_parseoci_fuzzer"
