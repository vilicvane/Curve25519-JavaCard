#!/usr/bin/env bash
#
# Builds the on-card test applet for org.suut.javacard.pki.curve25519.
#
# The applet is built against the *reconstructed* library, not against the original curve25519.jar,
# so the CAP can only be installed together with the CAP produced by ./build.sh. Both steps run here.
#
#   JAVA_HOME     JDK to use                          (default: /tmp/jdk11)
#   JC_KIT        JavaCard dev kit                    (default: <monoid-javacard>/libs-sdks/jc310b43_kit)
#   JOPX_VERSION  JOPX import version for the library (default: 1.24; cards with an older JCOPX need
#                 e.g. JOPX_VERSION=1.18)
#
# Usage: ./test/build-test.sh
#
# Outputs:
#   build/out/.../curve25519.cap                       the reconstructed library
#   build/test/out/.../cardtest.cap                    the test applet
#
set -euo pipefail

cd "$(dirname "$0")/.."

JDK=${JAVA_HOME:-/tmp/jdk11}
KIT=${JC_KIT:-/mnt/c/Projects/monoid-javacard/libs-sdks/jc310b43_kit}

JAVAC="$JDK/bin/javac"
JAVA="$JDK/bin/java"
API_JAR="$KIT/lib/api_classic-3.0.5.jar"
PLATFORM_EXP="$KIT/api_export_files_3.0.5"
SDK_CP="$KIT/lib/tools.jar:$KIT/lib/commons-cli-1.0.jar:$KIT/lib/commons-logging-1.1.jar"
CONVERTER=com.sun.javacard.converter.Main

APP_PACKAGE=org.suut.javacard.pki.curve25519.cardtest
APP_PACKAGE_AID=0xF0:0x43:0x55:0x52:0x56:0x45:0x01
APP_AID="$APP_PACKAGE_AID:0x01"
APP_CLASS="$APP_PACKAGE.Curve25519TestApplet"

CLASSES=build/test/classes
OUT=build/test/out

echo "== build library"
./build.sh

echo "== compile test applet"
rm -rf "$CLASSES" "$OUT"
mkdir -p "$CLASSES" "$OUT"
"$JAVAC" --release 7 -Xlint:-options -nowarn \
    -cp "$API_JAR:build/classes" \
    -d "$CLASSES" \
    test/applet/src/org/suut/javacard/pki/curve25519/cardtest/Curve25519TestApplet.java

class_major=$(od -An -tu1 -j6 -N2 "$CLASSES/org/suut/javacard/pki/curve25519/cardtest/Curve25519TestApplet.class" | awk '{print $1 * 256 + $2}')
if [ "$class_major" -ne 51 ]; then
    echo "error: class file major version is $class_major, the converter needs 51 (use --release 7)" >&2
    exit 1
fi

echo "== convert test applet"
"$JAVA" -cp "$SDK_CP" "$CONVERTER" \
    -classdir "$CLASSES" \
    -exportpath "$PLATFORM_EXP:build/out" \
    -target 3.0.5 \
    -out CAP EXP JCA \
    -d "$OUT" \
    -applet "$APP_AID" "$APP_CLASS" \
    "$APP_PACKAGE" "$APP_PACKAGE_AID" 1.0

echo "== built"
ls -l "$OUT/org/suut/javacard/pki/curve25519/cardtest/javacard/"
