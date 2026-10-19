# libs

Java Card jars that let the editor resolve the `javacard.*` imports. They are **not** part of the
build: `build.sh` reads its jars straight out of the development kit.

| File | Committed | Source | Used by |
| --- | --- | --- | --- |
| `api_classic-3.0.5.jar` | yes | `<kit>/lib/api_classic-3.0.5.jar` | `src/` and `stub/`, resolves `javacard.framework`, `javacard.security`, `javacardx.crypto` |
| `javacard-tools.jar` | no | `<kit>/lib/tools.jar` | `tools/ExpPatch.java`, resolves `com.sun.javacard.exportfile` |

`.vscode/settings.json` puts `libs/**/*.jar` on the project classpath, which is what makes
`The import javacard cannot be resolved` go away in VS Code / Cursor.

## `api_classic-3.0.5.jar`

The Java Card 3.0.5 classic API is not on Maven Central; it ships only inside the Oracle
development kit, so the jar is committed here to keep a fresh clone free of editor errors. It is
redistributed under the same informal convention as
[martinpaljak/oracle_javacard_sdks](https://github.com/martinpaljak/oracle_javacard_sdks): it is
Oracle's binary, not free software, and it is vendored for development only.

## `javacard-tools.jar`

The converter and export-file reader live in Oracle's `tools.jar`, which is 1.2 MB and is only
needed to work on `tools/ExpPatch.java`. It is git-ignored; fill it in with:

```sh
tools/ide-setup.sh
```

The script also refreshes `api_classic-3.0.5.jar`, so it stays in sync with the kit that `build.sh`
uses. `JC_KIT` selects the kit when it lives somewhere else.

To index `tools/ExpPatch.java` in the editor, add `tools` to `java.project.sourcePaths` in
`.vscode/settings.json` — that is left out by default so a clone without `javacard-tools.jar`
shows no errors.
