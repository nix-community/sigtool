#!/usr/bin/env bash

set -euo pipefail

: "${APPLE_CODESIGN:=/usr/bin/codesign}"
: "${OUR_SIGTOOL:=$(dirname "$0")/../sigtool}"
: "${OUR_CODESIGN:=$(dirname "$0")/../codesign}"

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

# Thin dylib for nested-bundle tests
if ! [ -e tmp/libnested.dylib ]; then
  cc -dynamiclib -o tmp/libnested.dylib lib.c
  # cc ad-hoc signs by default; start from an unsigned file
  $APPLE_CODESIGN --remove-signature tmp/libnested.dylib
fi

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

# Build an app bundle exercising the nested-bundle code paths, sign it with
# our codesign, and require Apple's codesign to accept it with --deep --strict.
# Covers: nested framework (with Versions/Current symlink layout and a
# symlinked header), nested .xpc, loose dylib under Frameworks/, symlinked
# resource, .lproj with locversion.plist, .DS_Store, PkgInfo.
write_info_plist() {
  local path=$1 id=$2 exec=$3
  cat > "$path" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
  <key>CFBundleIdentifier</key><string>$id</string>
  <key>CFBundleExecutable</key><string>$exec</string>
</dict></plist>
EOF
}

make_bundle_fixture() {
  local app=$1
  rm -rf "$app"
  local c=$app/Contents

  mkdir -p "$c/MacOS" "$c/Resources/en.lproj" "$c/Resources/Base.lproj"
  # cc ad-hoc signs its output on arm64; the fixture must start unsigned.
  cp tmp/test "$c/MacOS/Nested"
  $APPLE_CODESIGN --remove-signature "$c/MacOS/Nested"
  write_info_plist "$c/Info.plist" com.example.nested Nested
  printf 'APPL????' > "$c/PkgInfo"
  echo data > "$c/Resources/data.txt"
  ln -s data.txt "$c/Resources/link.txt"
  echo s > "$c/Resources/en.lproj/Localizable.strings"
  echo lv > "$c/Resources/en.lproj/locversion.plist"
  echo b > "$c/Resources/Base.lproj/Main.strings"
  echo ds > "$c/Resources/.DS_Store"
  echo v > "$c/version.plist"

  # Nested framework with the conventional symlink layout
  local fw=$c/Frameworks/Foo.framework
  mkdir -p "$fw/Versions/A/Resources" "$fw/Versions/A/Headers"
  cp tmp/libnested.dylib "$fw/Versions/A/Foo"
  write_info_plist "$fw/Versions/A/Resources/Info.plist" com.example.foo Foo
  echo h > "$fw/Versions/A/Headers/foo.h"
  ln -s foo.h "$fw/Versions/A/Headers/link.h"
  ln -s A "$fw/Versions/Current"
  ln -s Versions/Current/Foo "$fw/Foo"
  ln -s Versions/Current/Resources "$fw/Resources"

  # Loose dylib directly under Frameworks/
  cp tmp/libnested.dylib "$c/Frameworks/libnested.dylib"

  # Second Mach-O binary and a shell script next to the main executable
  cp tmp/libnested.dylib "$c/MacOS/helper"
  printf '#!/bin/sh\necho x\n' > "$c/MacOS/script.sh"
  chmod +x "$c/MacOS/script.sh"

  # Nested XPC service
  local xpc=$c/XPCServices/Svc.xpc
  mkdir -p "$xpc/Contents/MacOS" "$xpc/Contents/Resources"
  cp tmp/test.arm64-darwin "$xpc/Contents/MacOS/Svc"
  $APPLE_CODESIGN --remove-signature "$xpc/Contents/MacOS/Svc"
  write_info_plist "$xpc/Contents/Info.plist" com.example.svc Svc
  echo x > "$xpc/Contents/Resources/x.txt"
}

check_bundle() {
  local name=Nested.app
  local app=resigned/$name

  echo "Signing nested bundle and checking: $name"
  make_bundle_fixture "$app"

  local fail=0
  if ! $OUR_CODESIGN -s - "$app"; then
    echo "FAIL: our codesign failed on $name"
    fail=1
  elif ! $APPLE_CODESIGN --verify --deep --strict -vvv "$app"; then
    echo "FAIL: codesign --verify --deep --strict rejected $name"
    fail=1
  fi

  # Nested components must carry their own identifiers, and the outer seal
  # must record them as cdhash entries rather than plain file hashes.
  if [ "$fail" -eq 0 ]; then
    local cr=$app/Contents/_CodeSignature/CodeResources
    for entry in Frameworks/Foo.framework Frameworks/libnested.dylib XPCServices/Svc.xpc MacOS/helper; do
      if ! grep -A2 "<key>$entry</key>" "$cr" | grep -q '<key>cdhash</key>'; then
        echo "FAIL: no cdhash entry for $entry in $name"
        fail=1
      fi
    done
    if ! grep -q '<key>Resources/link.txt</key>' "$cr"; then
      echo "FAIL: symlink Resources/link.txt not sealed in $name"
      fail=1
    fi
    if grep -q 'locversion.plist</key>' "$cr"; then
      echo "FAIL: locversion.plist should be omitted from $name"
      fail=1
    fi
    # Extra Mach-O binaries must carry their own valid signature; plain
    # scripts next to the binary stay sealed by hash.
    if ! $APPLE_CODESIGN --verify --strict "$app/Contents/MacOS/helper"; then
      echo "FAIL: MacOS/helper is not validly signed in $name"
      fail=1
    fi
    if ! grep -A2 '<key>MacOS/script.sh</key>' "$cr" | grep -q '<key>hash2</key>'; then
      echo "FAIL: no hash2 entry for MacOS/script.sh in $name"
      fail=1
    fi
    for pair in "$app:com.example.nested" \
                "$app/Contents/Frameworks/Foo.framework:com.example.foo" \
                "$app/Contents/XPCServices/Svc.xpc:com.example.svc"; do
      local path=${pair%%:*} id=${pair##*:}
      # Capture first: grep -q closing the pipe early trips pipefail.
      local info
      info=$($APPLE_CODESIGN -dvvv "$path" 2>&1)
      if ! grep -q "^Identifier=$id\$" <<<"$info"; then
        echo "FAIL: $path does not have identifier $id"
        fail=1
      fi
    done
  fi

  if [ "$fail" -eq 0 ]; then
    echo "OK: $name"
  else
    failures+=("$name")
  fi

  echo
}

# Re-sign a binary that Apple's codesign signed with option flags and
# entitlements, preserving its metadata; identifier, flags (including the
# runtime version) and entitlements must survive. An explicit -o must replace
# the preserved flags, matching Apple's semantics.
check_preserve_metadata() {
  local name=preserve-metadata
  local bin=tmp/preserve

  echo "Checking --preserve-metadata against Apple's semantics"

  cp tmp/test.arm64-darwin "$bin"
  $APPLE_CODESIGN --remove-signature "$bin"
  $APPLE_CODESIGN -s - -i com.example.preserve \
      --entitlements entitlements.plist -o runtime,library,kill "$bin"
  local before
  before=$($APPLE_CODESIGN -dvvv "$bin" 2>&1 | grep -oE 'flags=[^ ]+')

  local fail=0
  if ! $OUR_CODESIGN -s - -f --preserve-metadata=identifier,entitlements,flags "$bin"; then
    echo "FAIL: our codesign failed re-signing $bin"
    fail=1
  else
    local info after
    info=$($APPLE_CODESIGN -dvvv "$bin" 2>&1)
    after=$(grep -oE 'flags=[^ ]+' <<<"$info")
    if [ "$before" != "$after" ]; then
      echo "FAIL: flags not preserved: before=$before after=$after"
      fail=1
    fi
    if ! grep -q '^Identifier=com.example.preserve$' <<<"$info"; then
      echo "FAIL: identifier not preserved"
      fail=1
    fi
    if ! $APPLE_CODESIGN -d --entitlements - "$bin" 2>/dev/null \
        | grep -q com.apple.security.cs.allow-jit; then
      echo "FAIL: entitlements not preserved"
      fail=1
    fi
    if ! $APPLE_CODESIGN --verify --strict "$bin"; then
      echo "FAIL: codesign --verify rejected the preserved re-sign"
      fail=1
    fi

    # An explicit -o replaces the preserved flags entirely.
    if ! $OUR_CODESIGN -s - -f --preserve-metadata=flags -o runtime "$bin"; then
      echo "FAIL: our codesign failed with --preserve-metadata=flags -o runtime"
      fail=1
    else
      after=$($APPLE_CODESIGN -dvvv "$bin" 2>&1 | grep -oE 'flags=0x[0-9a-f]+')
      if [ "$after" != "flags=0x10002" ]; then
        echo "FAIL: explicit -o did not replace preserved flags: $after"
        fail=1
      fi
    fi
  fi

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

check_bundle
check_preserve_metadata

if [ "${#failures[@]}" -eq 0 ]; then
  exit 0
else
  echo "Failed: ${failures[*]}"
  exit 1
fi
