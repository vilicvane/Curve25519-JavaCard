# Reconstructing the Curve25519 library from source

This document explains how `Curve25519.cap` was rebuilt from source, what had to be recovered from
the binary, and what has and has not been verified.

## What the original repository contains

The repository ships only binaries:

| Path | What it is |
|---|---|
| `Curve25519.cap` | the installed package; despite the extension it is a JAR (ZIP) holding the CAP components |
| `curve25519.jar` | the import artifact for other applets: six `.class` files, six API-only `.java` files whose bodies are `return 0`, and the real `curve25519.exp` |
| `sample/` | an ant-javacard applet that exercises the library |

There is no implementation source, and the CAP cannot be decompiled to source in the usual sense:
the arithmetic is not in the CAP at all. `Curve25519.cap` is a thin wrapper that stores a 32-byte
key, converts between the big-endian convention of the NXP JCOP firmware and the little-endian
conventions of RFC 7748 / RFC 8032, and calls into the closed JCOP eXtended ("JCOPX") package that
lives in card ROM.

## What the card actually provides

The imported packages in the CAP are:

| import token | AID | version |
|---|---|---|
| 0 | `a0000000620001` (`java/lang`) | 1.0 |
| 1 | `a0000000620102` (`javacard/security`) | 1.6 |
| 2 | `a0000000620101` (`javacard/framework`) | 1.6 |
| 3 | `d276000085304a434f5058` (JCOPX) | 1.24 |

A CAP file refers to another package only by *(package token, class token, method token)*. It does
not store the class name, the method name, or the argument types of an external call. The tokens
below were therefore recovered from the ConstantPool component (which carries the token triples) and
the Method component (which carries the call sites, argument counts and bytecode).

### Recovered JCOPX surface

Class token 1 — the curve operations, all static:

| method token | recovered signature | semantics |
|---|---|---|
| 2 | `short sign(JopxPrivateKey, byte type, byte[] hash, short hashOffset, short hashLength, byte[] signature, short signatureOffset)` | EdDSA signature; returns 64 |
| 3 | `short verify(JopxPublicKey, byte type, byte[] hash, short hashOffset, short hashLength, byte[] signature, short signatureOffset, short signatureLength)` | EdDSA verification; returns `0x5A5A` on success |
| 13 | `short keyAgreement(JopxPrivateKey, JopxPublicKey, byte type, byte[] output, short outputOffset)` | X25519; returns 32 |

The `type` argument is `0xA3` on the EdDSA path and `0xA4` on the X25519 path. Only these three
methods are reachable from `Curve25519.cap`; the other tokens of that class are never referenced and
their meaning is unknown.

Class token 11 — the key factory, all static:

| method token | recovered signature | semantics |
|---|---|---|
| 1 | `Object createKey(byte algorithm, byte memoryType)` | allocates a key; `algorithm` is one of the four `ALG_TYPE_*` values |
| 2 | `void genKeyPair(JopxPrivateKey, JopxPublicKey)` | fills in a fresh key pair |

Class tokens 9 and 10 — the private-key and public-key interfaces, both with the same seven methods:

| method token | signature |
|---|---|
| 0 | `void clearKey()` |
| 1 | `short getSize()` |
| 2 | `byte getType()` |
| 3 | `boolean isInitialized()` |
| 4 | `byte getKeyMemoryType()` |
| 5 | `void importKey(byte[] buffer, short offset, short length)` |
| 6 | `short exportKey(byte[] buffer, short offset)` |

In the CP these appear as the bytes `83 01 02` (sign), `83 01 03` (verify), `83 01 0d`
(keyAgreement), `83 0b 01` (createKey), `83 0b 02` (genKeyPair), and as class references
`83 09` / `83 0a`. Those byte sequences are the criterion for "the rebuilt CAP links against the
same card functions".

### Why the names are invented

Because the CAP stores no external names, the original class and method names of the JCOPX package
cannot be recovered from the shipped artifacts; no public JCOPX export file is available either
(the card vendor documents the API under NDA). The names in `stub/jopx/` are therefore descriptive
placeholders. This is harmless: the converter encodes only the tokens into the CAP, so any naming
that produces the same tokens yields an identically linked package. The stub is a build-time
placeholder and must never be installed on a card — it would collide with the ROM package.

## Source layout

```
src/org/suut/javacard/pki/curve25519/   the library, 8 files
  Curve25519Key.java                    interface: getKeyMemoryType()
  Curve25519PrivateKey.java             interface: getS/setS, extends PrivateKey
  Curve25519PublicKey.java              interface: getW/setW, extends PublicKey
  Curve25519KeyBuilder.java             buildKey(byte, byte), genKeyPair(...), ALG_TYPE_* constants
  Curve25519Signature.java              sign(...), verify(...)
  Curve25519KeyAgreement.java           keyExchange(...)
  Curve25519PrivateKeyImpl.java         package-private; forwards to a JCOPX private key
  Curve25519PublicKeyImpl.java          package-private; forwards to a JCOPX public key
stub/jopx/                              build-time JCOPX placeholder, never installed
  JcopxPrivateKey.java                  interface, 7 methods
  JcopxPublicKey.java                   interface, 7 methods
  JcopxCurve25519.java                  sign/verify/keyAgreement plus filler methods for token gaps
  JcopxKeyFactory.java                  createKey/genKeyPair plus a filler method
tools/ExpPatch.java                     rewrites the stub exp to the real JCOPX tokens
tools/cpdump.py                         prints the Import and ConstantPool components of a CAP
tools/ide-setup.sh                      refreshes libs/ from the kit, see Editor setup
libs/api_classic-3.0.5.jar              the Java Card API jar, committed, see libs/README.md
libs/javacard-tools.jar                 converter/javacard-tools jar, local only, git-ignored
build.sh                                the whole build, end to end
.vscode/settings.json                   classpath for the Java language server
```

The public API is unchanged: three interfaces, three classes, the same method descriptors, the same
exception behaviour.

The two implementation classes are package-private, so they are not exported (their class token is
255, as in the original). They hold the JCOPX key objects. The private-key implementation forwards
`getS`/`setS` straight through, because a private key is a 32-byte seed or scalar with no byte-order
conversion. The public-key implementation keeps a 32-byte transient buffer and reverses the bytes on
both directions, because the card works big-endian while the API is little-endian.

EdDSA signatures are also reversed in two halves of 32 bytes, because the card returns `R || S` in
big-endian while RFC 8032 uses little-endian for both.

## Build

Prerequisites:

* a JDK that can run the converter (JDK 8 or 11; the build was verified with Temurin 11),
* a JavaCard 3.0.5 development kit containing `lib/tools.jar`, `lib/api_classic-3.0.5.jar` and
  `api_export_files_3.0.5/`,
* `javac` has to emit class files of major version 51, which `--release 7` produces; the converter
  rejects newer class files.

```sh
./build.sh
```

The environment can be overridden:

```sh
JAVA_HOME=/path/to/jdk JC_KIT=/path/to/jc310b43_kit ./build.sh
```

`build.sh` runs six steps:

1. compile `stub/jopx/*.java` and check the class file version;
2. convert the stub package to CAP/EXP/JCA under `build/stub/`;
3. patch the stub export file's class and method tokens to the JCOPX tokens recovered above, with
   `tools/ExpPatch.java`, writing `build/jopx-exp/jopx/javacard/jopx.exp`;
4. compile `src/org/suut/javacard/pki/curve25519/*.java` against the platform API and the stub;
5. convert the library with `build/jopx-exp` on the export path, package AID
   `0xFF:0x00:0x02:0x55:0x19` version 1.0, target 3.0.5, integer support off;
6. list `build/out/org/suut/javacard/pki/curve25519/javacard/`.

Passing `--verify` additionally prints the Import and ConstantPool components of the freshly built
CAP so that the linkage can be checked without a card.

### Why the stub needs filler methods

The converter requires the method tokens of a class in an export file to be consecutive from 0. The
card uses method token 2, 3 and 13 on the operations class and 1 and 2 on the key factory, so the
stub declares unused filler methods to fill the gaps. The fillers are never called; they exist only
to make the token numbering legal.

## Editor setup

Without a build tool in the repository, the Java language server treats the folder as an *unmanaged*
project: it picks up `src/`, `stub/` and `sample/src/` and puts nothing but a JRE on the classpath.
`javacard.framework` and friends are not on Maven Central either, so every `javacard.*` import is
reported as unresolved:

```
The import javacard cannot be resolved
```

The fix is to point the language server at the Java Card API jar. The 3.0.5 classic API is not on
Maven Central either, so `libs/api_classic-3.0.5.jar` is committed: a fresh clone needs no setup
step. `.vscode/settings.json` puts it on the classpath:

```json
{
  "java.project.sourcePaths": ["src", "stub"],
  "java.project.referencedLibraries": ["libs/**/*.jar"]
}
```

`libs/javacard-tools.jar` is *not* committed. It is Oracle's 1.2 MB `tools.jar`, needed only to work
on `tools/ExpPatch.java`; `tools/ide-setup.sh` copies it out of the kit:

```sh
tools/ide-setup.sh            # or: JC_KIT=/path/to/jc310b43_kit tools/ide-setup.sh
```

The script also refreshes `api_classic-3.0.5.jar` so that it matches the kit `build.sh` uses. To
index `tools/ExpPatch.java` as well, add `"tools"` to `sourcePaths`; it is left out by default so
that a clone without `javacard-tools.jar` still shows no errors. After either change, reload the
window or run `Java: Clean Java Language Server Workspace`.

`sample/src` is deliberately left out of `sourcePaths`: it is a separate ant project that expects
`../curve25519.jar`, and its `0x40` handler has an unreachable `verify` call, so it would show
permanent errors next to the library. Build it on its own with `sample/build.xml`.

Only the API and tools jars are needed; the converter, the export files and the JDK are not, because
the editor never converts anything. Real builds still go through `./build.sh`, which forces
`--release 7`.

## Verification performed

All of this was executed on a Linux host:

* the converter reports `0 errors and 0 warnings` for the library;
* the rebuilt export file is **byte-for-byte identical** to `curve25519.exp` from `curve25519.jar`
  (1553 bytes, `cmp` is silent), so the class tokens, method tokens, access flags, descriptor pool
  and field constant values match the original exactly;
* `Exp2Text` renders the rebuilt export file identically to the original text form;
* the `Header`, `Import` and `StaticField` components are byte-for-byte identical to the original,
  including all four imported AIDs and versions;
* the ConstantPool has the same 25 entries and the same external references
  (`83 01 02`, `83 01 03`, `83 01 0d`, `83 0b 01`, `83 0b 02`, class references `83 09`, `83 0a`,
  `JCSystem.beginTransaction`, `commitTransaction`, `abortTransaction`,
  `Util.arrayFillNonAtomic`, `CryptoException.throwIt`); only the order of a few unrelated entries
  and the offsets of the internal constructor references differ, because the local converter build
  packs the components slightly differently;
* the rebuilt Method component has the same four exception handlers with the same catch types
  (`java/lang/Throwable` and `javacard/framework/TransactionException`), at shifted offsets;
* the CAP file version (2.1), runtime descriptor version (3.0), package AID and version, converter
  version and `Integer-Support-Required: FALSE` all match the original manifest;
* `src/`, `stub/` and `tools/ExpPatch.java` all compile against `libs/api_classic-3.0.5.jar` and
  `libs/javacard-tools.jar` alone, which is exactly the classpath the editor gets.

The CAP itself is *not* byte-identical, and should not be expected to be: the original was built
with a different converter build, which lays out methods and constant pool entries in its own order.
What matters for a library package is the export file (the interface other packages compile against)
and the token triples of the external calls, and both match.

## Known documentation discrepancies

These come from the original README and are kept as-is in the source:

* the `sign` javadoc says the returned length is "always 32", but the implementation returns 64, and
  `verify` requires 64;
* the `setS` javadoc says the length must be 32 and lists `ArrayIndexOutOfBoundsException` for short
  buffers, but the private-key path forwards to the card without a length check — the card reports
  the error. The public-key path does check `length != 32` and throws
  `CryptoException.ILLEGAL_VALUE`, exactly like the original bytecode;
* `buildKey` throws `CryptoException.NO_SUCH_ALGORITHM` (3) for an unknown algorithm, not
  `ILLEGAL_VALUE` (1), which the README does not mention.

One behaviour that is easy to get wrong: `sign` and `keyExchange` wrap `beginTransaction()` in the
`try` and, in the handler, call `abortTransaction()` inside its own `try`/`catch
(TransactionException)`. A failed commit has already rolled the transaction back, so aborting again
throws `TransactionException`; the original swallows it and rethrows the original exception. The
source reproduces that nesting, and the rebuilt CAP has the same two handler pairs as the original.

## Not verified

The J3R452 card had not arrived, so none of the following has been exercised:

* installation of the rebuilt CAP on a card (`gp.jar --load`);
* that the card's ROM JCOPX package really exposes those tokens with those calling conventions;
* functional Ed25519 / X25519 results;
* performance (the README claims about 220 ms per EdDSA signature and about 50 ms per X25519 key
  exchange).

Suggested card checks:

```sh
java -jar gp.jar --load build/out/org/suut/javacard/pki/curve25519/javacard/curve25519.cap
```

then build and install `sample/` (it imports `../curve25519.jar`, so replace that import with the
rebuilt `curve25519.exp`, or regenerate the jar from `build/out`), and drive the APDUs the sample
documents: `00 10 00 00 00` (Ed25519 public key), `00 10 01 00 00` (X25519 public key),
`00 20 00 00 40 <sha512> 00` (sign), `00 40 00 00 80 <sha512><signature>` (verify),
`00 30 00 00 20 <peer public key> 00` (key exchange).

Note that `sample/src/.../Curve25519Test.java` has a pre-existing bug that was intentionally not
touched: in the `0x40` branch, `verify(...)` sits after a `throw`, so it is unreachable and the
verify APDU always fails. Fix it before trusting that command.

## Notes

* `build/` is ignored by git; `*.cap` and `*.jar` are ignored too, so the built artifacts are not
  committed. Rebuild with `./build.sh` whenever needed.
* `curve25519.cap` and `curve25519.jar` in the repository root are the original binaries and are not
  modified by the build.
