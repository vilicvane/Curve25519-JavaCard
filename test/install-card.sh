#!/usr/bin/env bash
#
# Deploys the reconstructed library and the test applet onto a physical card.
#
# The CAP files are copied to a Windows visible directory first, because gp.exe is a Windows binary:
# it is started with that directory as its working directory, so plain file names can be used.
#
# Usage:
#   ./test/install-card.sh                 build, delete an older deployment, load both CAPs
#   ./test/install-card.sh --no-build      use the CAPs that are already in build/
#   ./test/install-card.sh --uninstall     only delete the applet and the library package
#   ./test/install-card.sh --keep          do not delete an older deployment before loading
#
# Environment:
#   GP          gp.exe                          (default: /mnt/c/Utilities/bin/gp.exe)
#   GP_KEY      GlobalPlatform keys             (default: the well known dev keys 4041..4F)
#   CARD_STAGE  Windows visible staging dir     (default: %TEMP%\curve25519-test\caps)
#
# The card must already use the development keys; a factory keyed card has to be rekeyed first,
# for example:
#
#   gp.exe --key-enc ... --key-mac ... --key-dek ... --lock 404142434445464748494A4B4C4D4E4F
#
set -euo pipefail

cd "$(dirname "$0")/.."
REPO=$(pwd -P)

GP=${GP:-/mnt/c/Utilities/bin/gp.exe}
GP_KEY=${GP_KEY:-404142434445464748494A4B4C4D4E4F}

LIB_PACKAGE_AID=FF00025519
APP_PACKAGE_AID=F0435552564501
APP_INSTANCE_AID=F043555256450101

LIB_CAP=build/out/org/suut/javacard/pki/curve25519/javacard/curve25519.cap
APP_CAP=build/test/out/org/suut/javacard/pki/curve25519/cardtest/javacard/cardtest.cap

BUILD=true
REMOVE=true
UNINSTALL_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --no-build) BUILD=false ;;
        --keep) REMOVE=false ;;
        --uninstall) UNINSTALL_ONLY=true ;;
        *)
            echo "usage: $0 [--no-build] [--keep] [--uninstall]" >&2
            exit 2
            ;;
    esac
done

if $BUILD && ! $UNINSTALL_ONLY; then
    ./test/build-test.sh
fi

if ! $UNINSTALL_ONLY; then
    for cap in "$LIB_CAP" "$APP_CAP"; do
        if [ ! -f "$cap" ]; then
            echo "error: $cap is missing, run ./test/build-test.sh first" >&2
            exit 1
        fi
    done
fi

# Windows path for gp.exe, POSIX path for this shell.
#
# CARD_STAGE is a WSL path by default; translate the /mnt/<drive>/ prefix into <DRIVE>:\ so that
# gp.exe can be pointed at the same directory with the file names it expects.
if [ -z "${CARD_STAGE:-}" ]; then
    user=$(basename "$HOME")
    CARD_STAGE=/mnt/c/Users/$user/AppData/Local/Temp/curve25519-test/caps
fi
case "$CARD_STAGE" in
    /mnt/[a-z]/*)
        drive=$(printf '%s' "$CARD_STAGE" | cut -c6)
        rest=$(printf '%s' "$CARD_STAGE" | cut -c8-)
        CARD_STAGE_WIN="$(printf '%s' "$drive" | tr '[:lower:]' '[:upper:]'):\\${rest//\//\\}"
        ;;
    *)
        echo "error: CARD_STAGE must be under /mnt/<drive>/ on WSL, got: $CARD_STAGE" >&2
        exit 1
        ;;
esac

if [ ! -x "$GP" ] && [ ! -f "$GP" ]; then
    echo "error: gp.exe not found at $GP, set GP to its path" >&2
    exit 1
fi

gp() {
    "$GP" --key-enc "$GP_KEY" --key-mac "$GP_KEY" --key-dek "$GP_KEY" "$@"
}

mkdir -p "$CARD_STAGE"
cd "$CARD_STAGE"

# gp wants bare hexadecimal AIDs, without the usual 0x prefixes.
if $REMOVE; then
    echo "== delete the previous deployment (ok if it is not there)"
    gp --delete "$APP_INSTANCE_AID" >/dev/null 2>&1 || true
    gp --delete "$APP_PACKAGE_AID" >/dev/null 2>&1 || true
    gp --delete "$LIB_PACKAGE_AID" >/dev/null 2>&1 || true
fi

if $UNINSTALL_ONLY; then
    echo "== removed"
    gp --list
    exit 0
fi

cp "$REPO/$LIB_CAP" curve25519.cap
cp "$REPO/$APP_CAP" cardtest.cap

echo "== load the library"
gp --load curve25519.cap

echo "== load and install the test applet"
gp --install cardtest.cap

echo
echo "== installed (staged in $CARD_STAGE_WIN)"
gp --list

echo
echo "Now run the on-card tests:"
echo "    python3 -u test/card_test.py --timing"
