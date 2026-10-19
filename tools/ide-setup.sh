#!/bin/sh
#
# Fill libs/ with the Java Card jars the editor can use.
#
# libs/api_classic-3.0.5.jar is committed, so a fresh clone already resolves
# the javacard.* imports; this script refreshes it from the kit and also copies
# the optional converter/export-file jar, which is git-ignored because only
# tools/ExpPatch.java needs it.
#
# Usage:
#   tools/ide-setup.sh
#   JC_KIT=/path/to/jc310b43_kit tools/ide-setup.sh
#
set -eu

cd "$(dirname "$0")/.."

die() {
    echo "error: $*" >&2
    exit 1
}

# A kit is usable when it has both the platform API and the converter tools.
find_kit() {
    for kit in \
        "${JC_KIT:-}" \
        /mnt/c/Projects/monoid-javacard/libs-sdks/jc310b43_kit \
        "$HOME/monoid-javacard/libs-sdks/jc310b43_kit" \
        "$HOME/projects/monoid-javacard/libs-sdks/jc310b43_kit" \
        "$HOME/oracle_javacard_sdks/jc310b43_kit"
    do
        if [ -n "$kit" ] && [ -f "$kit/lib/api_classic-3.0.5.jar" ] && [ -f "$kit/lib/tools.jar" ]; then
            echo "$kit"
            return 0
        fi
    done
    return 1
}

kit=$(find_kit) || die 'no Java Card development kit found; set JC_KIT to a directory such as /path/to/jc310b43_kit'

[ -f "$kit/lib/api_classic-3.0.5.jar" ] || die "$kit/lib/api_classic-3.0.5.jar not found"
[ -f "$kit/lib/tools.jar" ] || die "$kit/lib/tools.jar not found"

mkdir -p libs
cp "$kit/lib/api_classic-3.0.5.jar" libs/api_classic-3.0.5.jar
cp "$kit/lib/tools.jar" libs/javacard-tools.jar

echo "copied from $kit"
ls -l libs/*.jar
echo
echo 'Now reload the editor window, or run "Java: Clean Java Language Server Workspace",'
echo 'so that libs/**/*.jar is added to the project classpath.'
echo
echo 'To also index tools/ExpPatch.java, add "tools" to java.project.sourcePaths in .vscode/settings.json.'
