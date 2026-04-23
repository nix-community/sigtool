#!/usr/bin/env bash

set -euo pipefail

mkdir -p resigned tmp apple_signed stripped

archs=(arm64-darwin x86_64-darwin)

# Thins
for arch in "${archs[@]}"; do
  out=tmp/test.$arch
  if ! [ -e "$out" ]; then
    cc -target "$arch" -o "$out" -DMESSAGE="\"$arch\"" main.c
  fi
  files+=("$out")
done

# Fat
lipo -create "${files[@]}" -output tmp/test
files+=(tmp/test)

failures=()

resign() {
  local input=$1

  local name
  name=$(basename "$input")
  local out=resigned/$name

  echo "Re-signing and checking: $name"

  allocate_archs=()
  while read -r arch sigsize; do
    sigsize=$(( ((sigsize + 15) / 16) * 16 + 1024 ))
    allocate_archs+=(-a "$arch" "$sigsize")
  done < <(sigtool --file "$input" size)

  codesign_allocate -i "$input" "${allocate_archs[@]}" -o "$out"
  sigtool --identifier "$name" --file "$out" inject

  # This must be actual codesign
  if codesign --verify -vvv "$out"; then
    echo "OK: $name"
  else
    echo "FAIL: $name"
    failures+=("$name")
  fi

  echo
}

# Check --remove-signature matches Apple byte-for-byte and that the
# stripped file re-signs and verifies. Thin only.
remove_roundtrip() {
  local input=$1
  local name
  name=$(basename "$input")

  echo "Strip-and-resign: $name"

  local ours=stripped/$name.ours
  local theirs=stripped/$name.theirs
  cp "$input" "$ours"
  cp "$input" "$theirs"

  # Our drop-in matches Apple byte-for-byte on thin Mach-O.
  "$(dirname "$0")/../codesign" --remove-signature "$ours"
  /usr/bin/codesign --remove-signature "$theirs"
  if ! cmp -s "$ours" "$theirs"; then
    echo "FAIL: --remove-signature output differs from Apple's for $name"
    failures+=("$name-strip")
    echo
    return
  fi

  # Stripped file must be re-signable and the result must verify.
  if CODESIGN_ALLOCATE=codesign_allocate \
       "$(dirname "$0")/../codesign" -s - -f "$ours" \
     && codesign --verify -vvv "$ours"; then
    echo "OK: $name-strip"
  else
    echo "FAIL: re-sign after strip failed for $name"
    failures+=("$name-strip")
  fi
  echo
}

for f in "${files[@]}"; do
  resign "$f"
done

for arch in "${archs[@]}"; do
  remove_roundtrip "tmp/test.$arch"
done

if [ "${#failures[@]}" -eq 0 ]; then
  exit 0
else
  echo "Failed: ${failures[*]}"
  exit 1
fi
