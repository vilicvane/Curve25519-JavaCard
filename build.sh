#!/usr/bin/env bash
#
# Rebuilds org.suut.javacard.pki.curve25519 (the Curve25519 JavaCard library) from source.
#
# The build needs a JavaCard 3.0.5 development kit that ships the converter, plus a JDK that can
# run it. Both are taken from the environment when present:
#
#   JAVA_HOME     JDK to use           (default: /tmp/jdk11)
#   JC_KIT        JavaCard dev kit     (default: <monoid-javacard>/libs-sdks/jc310b43_kit)
#   JOPX_VERSION  JOPX package version the import is compiled against (default: 1.24)
#
# JOPX_VERSION is the version written into the CAP's import of the card's JOPX package. A card can
# only load a package whose requested import version is not newer than the JCOPX package it
# provides, so a card with an older JCOPX needs e.g. JOPX_VERSION=1.18 ./build.sh.
#
# Usage: ./build.sh [--verify]
#
# The build is three steps:
#   1. compile the JOPX stub package (build-time placeholder, never installed on a card)
#   2. run the converter on the stub package and patch its exp so that the class/method tokens
#      match the ones the card's JOPX implementation exposes
#   3. compile and convert the actual library against the patched stub exp
#
# With --verify the Import and ConstantPool components of the built CAP are printed as well, which
# is enough to check that the package links against the card's JOPX functions.
#
set -euo pipefail

cd "$(dirname "$0")"

VERIFY=false
case ${1:-} in
    '') ;;
    --verify) VERIFY=true ;;
    *) echo "usage: $0 [--verify]" >&2; exit 2 ;;
esac

JDK=${JAVA_HOME:-/tmp/jdk11}
KIT=${JC_KIT:-/mnt/c/Projects/monoid-javacard/libs-sdks/jc310b43_kit}

JAVAC="$JDK/bin/javac"
JAVA="$JDK/bin/java"
API_JAR="$KIT/lib/api_classic-3.0.5.jar"
PLATFORM_EXP="$KIT/api_export_files_3.0.5"
SDK_CP="$KIT/lib/tools.jar:$KIT/lib/commons-cli-1.0.jar:$KIT/lib/commons-logging-1.1.jar"

CONVERTER=com.sun.javacard.converter.Main

JOPX_AID=0xD2:0x76:0x00:0x00:0x85:0x30:0x4A:0x43:0x4F:0x50:0x58
JOPX_VERSION=${JOPX_VERSION:-1.24}
JOPX_PACKAGE=jopx

PACKAGE=org.suut.javacard.pki.curve25519
PACKAGE_AID=0xFF:0x00:0x02:0x55:0x19
PACKAGE_VERSION=1.0

BUILD=build
STUB_CLASSES="$BUILD/stub-classes"
STUB_OUT="$BUILD/stub"
STUB_EXP_ROOT="$BUILD/jopx-exp"
CLASSES="$BUILD/classes"
OUT="$BUILD/out"

[ -x "$JAVAC" ] || { echo "javac not found at $JAVAC (set JAVA_HOME)" >&2; exit 1; }
[ -f "$KIT/lib/tools.jar" ] || { echo "JavaCard kit not found at $KIT (set JC_KIT)" >&2; exit 1; }
[ -d "$PLATFORM_EXP" ] || { echo "missing platform export files: $PLATFORM_EXP" >&2; exit 1; }

rm -rf "$BUILD"
mkdir -p "$STUB_CLASSES" "$STUB_OUT" "$STUB_EXP_ROOT" "$CLASSES" "$OUT"

echo "== 1/6 compile JOPX stub"
"$JAVAC" --release 7 -Xlint:-options -nowarn \
    -cp "$API_JAR" \
    -d "$STUB_CLASSES" \
    stub/jopx/*.java

# The converter only accepts class files of major version 51 (Java 7), so check instead of letting
# it fail with its own message.
class_major=$(od -An -tu1 -j6 -N2 "$STUB_CLASSES/jopx/JcopxCurve25519.class" | awk '{print $1 * 256 + $2}')
if [ "$class_major" -ne 51 ]; then
    echo "error: class file major version is $class_major, the converter needs 51 (use --release 7)" >&2
    exit 1
fi

echo "== 2/6 convert JOPX stub to CAP/EXP/JCA"
"$JAVA" -cp "$SDK_CP" "$CONVERTER" \
    -classdir "$STUB_CLASSES" \
    -exportpath "$PLATFORM_EXP" \
    -target 3.0.5 \
    -out CAP EXP JCA \
    -d "$STUB_OUT" \
    "$JOPX_PACKAGE" "$JOPX_AID" "$JOPX_VERSION"

echo "== 3/6 patch JOPX exp tokens"
mkdir -p "$BUILD/tools" "$STUB_EXP_ROOT/jopx/javacard"
"$JAVAC" -nowarn -cp "$KIT/lib/tools.jar" -d "$BUILD/tools" tools/ExpPatch.java
"$JAVA" -cp "$KIT/lib/tools.jar:$BUILD/tools" ExpPatch \
    "$STUB_OUT/jopx/javacard/jopx.exp" \
    "$STUB_EXP_ROOT/jopx/javacard/jopx.exp"

echo "== 4/6 compile $PACKAGE"
"$JAVAC" --release 7 -Xlint:-options -nowarn \
    -cp "$API_JAR:$STUB_CLASSES" \
    -d "$CLASSES" \
    src/org/suut/javacard/pki/curve25519/*.java

echo "== 5/6 convert $PACKAGE to CAP/EXP/JCA"
"$JAVA" -cp "$SDK_CP" "$CONVERTER" \
    -classdir "$CLASSES" \
    -exportpath "$PLATFORM_EXP:$STUB_EXP_ROOT" \
    -target 3.0.5 \
    -out CAP EXP JCA \
    -d "$OUT" \
    "$PACKAGE" "$PACKAGE_AID" "$PACKAGE_VERSION"

echo "== 6/6 done"
ls -l "$OUT/org/suut/javacard/pki/curve25519/javacard/"

if $VERIFY; then
    echo
    echo "== verify JOPX linkage"
    python3 tools/cpdump.py "$OUT/org/suut/javacard/pki/curve25519/javacard/curve25519.cap"
fi
