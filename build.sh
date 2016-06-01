#!/bin/sh
set -e
cd "$(dirname "$0")"

if [ -e nimenv.local ]; then
  echo 'nimenv.local exists. You may use `nimenv build` instead of this script.'
  #exit 1
fi

mkdir -p .nimenv/nim
mkdir -p .nimenv/deps

NIMHASH=cd61f5e5768d4063596d6df578ae9bb5f9d52430773542987e91050b848cb1a9
if ! [ -e .nimenv/nimhash -a \( "$(cat .nimenv/nimhash)" = "$NIMHASH" \) ]; then
  echo "Downloading Nim http://nim-lang.org/download/nim-0.13.0.tar.xz (sha256: $NIMHASH)"
  wget http://nim-lang.org/download/nim-0.13.0.tar.xz -O .nimenv/nim.tar.xz
  if ! [ "$(sha256sum < .nimenv/nim.tar.xz)" = "$NIMHASH  -" ]; then
    echo "verification failed"
    exit 1
  fi
  echo "Unpacking Nim..."
  rm -r .nimenv/nim
  mkdir -p .nimenv/nim
  cd .nimenv/nim
  tar xJf ../nim.tar.xz
  mv nim-*/* .
  echo "Building Nim..."
  make -j$(getconf _NPROCESSORS_ONLN)
  cd ../..
  echo $NIMHASH > .nimenv/nimhash
fi

get_dep() {
  set -e
  cd .nimenv/deps
  name="$1"
  url="$2"
  hash="$3"
  srcpath="$4"
  new=0
  if ! [ -e "$name" ]; then
    git clone --recursive "$url" "$name"
    new=1
  fi
  if ! [ "$(cd "$name" && git rev-parse HEAD)" = "$hash" -a $new -eq 0 ]; then
     cd "$name"
     git fetch --all
     git checkout -q "$hash"
     git submodule update --init
     cd ..
  fi
  cd ../..
  echo "path: \".nimenv/deps/$name$srcpath\"" >> nim.cfg
}

echo "path: \".\"" > nim.cfg



echo '@if release:
  gcc.options.always = "-w -fno-strict-overflow"
  gcc.cpp.options.always = "-w -fno-strict-overflow"
  clang.options.always = "-w -fno-strict-overflow"
  clang.cpp.options.always = "-w -fno-strict-overflow"

  passC:"-ffunction-sections -fdata-sections -flto"
  passL:"-Wl,--gc-sections -flto"
@end' >> nim.cfg

mkdir -p bin
ln -sf ../.nimenv/nim/bin/nim bin/nim

echo "building dedup"; bin/nim c -d:release --out:"$PWD/bin/dedup" dedup.nim
