#!/usr/bin/env bash

set -euo pipefail

: "${APPLE_CODESIGN:=/usr/bin/codesign}"
: "${OUR_SIGTOOL:=$(dirname "$0")/../sigtool}"

mkdir -p resigned tmp apple_signed

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
  done < <($OUR_SIGTOOL --file "$input" size)

  codesign_allocate -i "$input" "${allocate_archs[@]}" -o "$out"
  $OUR_SIGTOOL --identifier "$name" --file "$out" inject

  # This must be actual codesign
  if $APPLE_CODESIGN --verify -vvv "$out"; then
    echo "OK: $name"
  else
    echo "FAIL: $name"
    failures+=("$name")
  fi

  echo
}

resign_with_der_entitlements() {
  local input=$1
  local entitlements=$2

  local name
  name=$(basename "$input").der
  local out=resigned/$name

  echo "Re-signing with DER entitlements and checking: $name"

  allocate_archs=()
  while read -r arch sigsize; do
    sigsize=$(( ((sigsize + 15) / 16) * 16 + 1024 ))
    allocate_archs+=(-a "$arch" "$sigsize")
  done < <($OUR_SIGTOOL --file "$input" --entitlements "$entitlements" \
                   --generate-entitlement-der size)

  codesign_allocate -i "$input" "${allocate_archs[@]}" -o "$out"
  $OUR_SIGTOOL --identifier "$name" --file "$out" \
          --entitlements "$entitlements" --generate-entitlement-der inject

  local fail=0

  # The real codesign must accept the signature.
  if ! $APPLE_CODESIGN --verify -vvv "$out"; then
    echo "FAIL: codesign --verify rejected $name"
    fail=1
  fi

  # codesign -d must parse our DER blob and round-trip the keys.
  local parsed
  parsed=$($APPLE_CODESIGN -d --entitlements - "$out" 2>/dev/null || true)
  for key in com.apple.security.cs.allow-jit com.example.string com.example.nested; do
    if ! grep -q "$key" <<<"$parsed"; then
      echo "FAIL: codesign -d --entitlements missing key '$key' for $name"
      fail=1
    fi
  done

  if [ "$fail" -eq 0 ]; then
    echo "OK: $name"
  else
    failures+=("$name")
  fi

  echo
}

for f in "${files[@]}"; do
  resign "$f"
done

for f in "${files[@]}"; do
  resign_with_der_entitlements "$f" entitlements.plist
done

if [ "${#failures[@]}" -eq 0 ]; then
  exit 0
else
  echo "Failed: ${failures[*]}"
  exit 1
fi
