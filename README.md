# Ed25519 and X25519 on NXP JCOP 4.5 / J3R452 smartcards

This is a **hardware** implementation for the J3R452 JavaCard. This package is a lightweight wrapper
around the private NXP APIs for Ed25519 and X25519 which allow you to actually fully do what your
J3R452 is capable of without selling your soul to NXP.

This package also hides the peculiarities of the NXP APIs which has its public keys and signatures
in big-endian format. Thus this package uses the regular little-endian format used everywhere else.

## Installation and usage

Install the package with [GlobalPlatformPro](https://github.com/martinpaljak/GlobalPlatformPro):

```sh
java -jar gp.jar --load Curve25519.cap
```

Then use the export files by adding the `<import jar="curve25519.jar" />` directive in the `<cap />` tag in your `build.xml`
when building with [ant-javacard](https://github.com/martinpaljak/ant-javacard).

## Sample

See the [sample](sample/) for code and usage instructions.

## Source implementation

The published repository contains only the compiled `Curve25519.cap` and the export jar: the Ed25519
and X25519 arithmetic lives in the NXP JCOP firmware, and the package itself is a thin wrapper that
stores 32-byte keys, reverses byte order and calls the private JCOP APIs. That source was not
published.

This repository now also contains a source reconstruction of that wrapper, recovered by disassembling
the released CAP file and reimplementing what it does:

```
src/org/suut/javacard/pki/curve25519/   the library, 8 files (the public API is unchanged)
stub/jopx/                              build-time placeholder for the JCOP package, never installed
tools/ExpPatch.java                     rewrites the stub export file to the recovered JCOP tokens
tools/cpdump.py                         prints the Import and ConstantPool components of a CAP
test/                                   an on-card test applet and its driver
docs/RECONSTRUCTION.md                  how the wrapper was recovered, and what was verified
```

Build it with:

```sh
./build.sh
```

which needs a JavaCard 3.0.5 development kit (`JC_KIT` overrides its location) and a JDK, and writes
`build/out/org/suut/javacard/pki/curve25519/javacard/curve25519.{cap,exp,jca}`. The generated export
file is byte-for-byte identical to the one inside `curve25519.jar`, so code compiled against the
original export file links against this implementation unchanged. The CAP itself is not byte-identical
to the released one — a different converter and a different method layout — but it references the same
JCOP package, class tokens and method tokens.

The `stub/` package exists only to give the converter something to link against at build time. It
must never be installed: its AID is the AID of the JCOP package that is already in the card's ROM.
Only `curve25519.cap` is meant for the card.

The library has been deployed and exercised on a J3R452: `test/build-test.sh` builds a test applet,
`test/install-card.sh` loads both CAPs through `gp.exe`, and `test/card_test.py` drives the applet and
compares every result with an independent RFC 8032 / RFC 7748 implementation. Ed25519 signatures, the
X25519 shared secret and both key generators match, and 20 of 20 checks pass. See
`docs/RECONSTRUCTION.md` for the details, including an X25519 byte-order quirk that the original
README does not mention.

### Attribution

The source reconstruction, the build script, the reconstruction notes and the editor configuration
were written by **deepseek-flash** (provider `deepseek-official`, through the DeepSeek Harness coding
agent) on 2026-10-20. The JCOP token semantics were inferred from the bytecode of the released CAP
file, which is exactly the review path the Security section below invites; they have not been
confirmed on a card yet, because the J3R452 was not available.

## API

`Curve25519Signature` and `Curve25519KeyAgreement` need instances to be allocated with `new` in order to allocate
buffers for reversing public key and signature bytes to match the little-endian formats of RFC 7748 and RFC 8032.

An EdDSA signature takes about 220 ms while a X25519 key exchange takes about 50 ms.

### Package imports

```java
import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519KeyAgreement;
import org.suut.javacard.pki.curve25519.Curve25519Signature;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;
```

### Keys and key generation

#### `Curve25519Key`
```java
/**
 * Interface common to all types of Curve25519 keys
 */
public interface Curve25519Key {
    /**
     * @return One of the JCSystem.MEMORY_TYPE_* constants
     */
    public byte getKeyMemoryType();
}
```

#### `Curve25519PrivateKey`
```java
/**
 * Interface for private Curve25519 keys
 */
public interface Curve25519PrivateKey extends PrivateKey, Curve25519Key {
    /**
     * Reads the private key into a buffer.
     *
     * @param buffer The buffer in which to write the private key
     * @param offset The offset in buffer at which to start writing
     * @return       The length of data written to buffer (always 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null.
     * @throws javacard.security.CryptoException with reason CryptoException.ILLEGAL_VALUE if the size
     *     of key is not supported (i.e. different than 32).
     */
    public short getS(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the private key from a buffer.
     *
     * @param buffer The buffer from which to read the new private key
     * @param offset The offset in buffer from which to start reading
     * @param length The length of the new private key (must be 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if buffer is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason CryptoException.UNINITIALIZED_KEY if the
     *     key has not been initialized.
     */
    public void setS(byte[] buffer, short offset, short length) throws CryptoException;
}
```

#### `Curve25519PublicKey`
```java
/**
 * Interface for public Curve25519 keys
 */
public interface Curve25519PublicKey extends PublicKey, Curve25519Key {
    /**
     * Reads the public key into a buffer.
     *
     * @param buffer The buffer in which to write the public key
     * @param offset The offset in buffer at which to start writing
     * @return       The length of data written to the buffer (always 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null.
     * @throws javacard.security.CryptoException with reason CryptoException.ILLEGAL_VALUE if the size
     *     of key is not supported (i.e. different than 32).
     */
    public short getW(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the public key from a buffer.
     *
     * @param buffer The buffer in which to read the new public key
     * @param offset The offset in buffer from which to start reading
     * @param length The length of the new public key (must be 32)
     * 
     * @throws java.lang.NullPointerException if buffer is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if buffer is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason CryptoException.UNINITIALIZED_KEY if the
     *     key has not been initialized.
     */
    public void setW(byte[] buffer, short offset, short length) throws CryptoException;
}
```

#### `Curve25519KeyBuilder`
```java
/**
 * Class for making and generating Curve25519 keys
 */
public final class Curve25519KeyBuilder {
    /**
     * Algorithm type for private EdDSA keys
     */
    public static final byte ALG_TYPE_EDDSA_PRIVATE = -127;
    /**
     * Algorithm type for public EdDSA keys
     */
    public static final byte ALG_TYPE_EDDSA_PUBLIC = -128;
    /**
     * Algorithm type for private X25519 keys
     */
    public static final byte ALG_TYPE_X25519_PRIVATE = -125;
    /**
     * Algorithm type for public X25519 keys
     */
    public static final byte ALG_TYPE_X25519_PUBLIC = -126;

    private Curve25519KeyBuilder() {}

    /**
     * Builds a Curve25519 key
     * 
     * @param algo       One of the ALG_TYPE_* constants
     * @param memoryType One of the JCSystem.MEMORY_TYPE_* constants
     * 
     * @return The key instance, to cast to Curve25519PublicKey or Curve25519PrivateKey
     * 
     * @throws javacard.security.CryptoException with the following reason codes:
     *     - CryptoException.NO_SUCH_ALGORITHM if the requested algorithm associated with the specified
     *           algorithmic type, or memory storage type for key, or size of key or key encryption
     *           interface requested is not supported.
     *     - CryptoException.ILLEGAL_VALUE if the requested memory type is not allowed.
     */
    public static Key buildKey(byte algo, byte memoryType) throws CryptoException;

    /**
     * Generates or regenerates a key pair
     * 
     * @param privateKey An instance of Curve25519PrivateKey
     * @param publicKey  An instance of Curve25519PublicKey
     * 
     * @throws javacard.security.CryptoException with the following reason codes:
     *     - CryptoException.ILLEGAL_VALUE - if the provided keys do not have the correct type or are NULL.
     */
    public static void genKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CryptoException;
}
```

### Signature and key exchange

#### `Curve25519KeyAgreement`
```java
/**
 * Class for X25519 key agreement
 */
public final class Curve25519KeyAgreement {
    /**
     * Constructor for the key agreement object
     * 
     * The constructor allocates a CLEAR_ON_DESELECT buffer in order to reverse the bytes into
     * the usual little-endian format specified in RFC 7748.
     */
    public Curve25519KeyAgreement();

    /**
     * X25519 key agreement
     * 
     * @param privateKey The local private key
     * @param publicKey  The remote public key
     * @param outBuff    The buffer into which to write the shared secret
     * @param outOffset  The offset in buffer at which to write the shared secret
     * @return           Length of the shared secret (always 32)
     * 
     * @throws javacard.security.CryptoException with the following reason codes:
     *     - CryptoException.UNINITIALIZED_KEY if the key is not initialized.
     *     - CryptoException.ILLEGAL_VALUE if the Key is inconsistent with the signature algorithm.
     *     - CryptoException.NO_SUCH_ALGORITHM
     *         - if publicKey is not an instance of Curve25519PublicKey.
     *         - if privateKey is not an instance of Curve25519PrivateKey.
     *         - if X25519 is not available (extended IoT module is not present).
     */
    public short keyExchange(PrivateKey privateKey, PublicKey publicKey, byte[] outBuff, short outOffset) throws CryptoException;
}
```

#### `Curve25519Signature`
```java
/**
 * Class for making and verifying Ed25519 signatures
 */
public final class Curve25519Signature {
    /**
     * Constructor for the EdDSA signature object.
     * 
     * The constructor allocates CLEAR_ON_DESELECT storage to be able to reverse the signature r and s components
     * to match the little-endian format specified in RFC 8032.
     */
    public Curve25519Signature();

    /**
     * Sign with EdDSA on Curve25519.
     * 
     * This uses the Ed25519 algorithm specified in RFC 8032.
     * 
     * @param privateKey The private key used for signing
     * @param inBuff     The data to sign
     * @param inOffset   The offset in inBuff at which to start reading the data
     * @param inLength   The length of data to sign
     * @param outBuff    The buffer in which to write the signature
     * @param outOffset  The offset into outBuff at which to write the signature
     * @return           The length of the signature written to outBuff (always 32)
     * 
     * @throws java.lang.NullPointerException if privateKey/inBuff/outBuff is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if the offset of inBuff/outBuff is negative or if the array
     *     length is less than the input length
     * @throws javacard.security.CryptoException with the following reason codes:
     *     - CryptoException.ILLEGAL_VALUE - if the Key is inconsistent with the signature algorithm.
     *     - CryptoException.UNINITIALIZED_KEY if the key is not initialized.
     *     - CryptoException.NO_SUCH_ALGORITHM - if Ed25519 support is not available (extended IoT module is not present).
     */
    public short sign(PrivateKey privateKey, byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) throws CryptoException;

    /**
     * Verify an EdDSA signature on Curve25519.
     * 
     * This uses the Ed25519 algorithm specified in RFC 8032.
     * 
     * @param publicKey       The public key used for verification
     * @param inBuff          The data for which the signature was made
     * @param inOffset        The offset in inBuff at which to start reading the data
     * @param inLength        The length of data to sign
     * @param signatureBuff   The buffer from which to read the signature
     * @param signatureOffset The offset into outBuff from which to read the signature
     * @return                true if the signature matches, false otherwise
     */
    public boolean verify(PublicKey publicKey, byte[] inBuff, short inOffset, short inLength, byte[] signatureBuff, short signatureOffset, short signatureLength) throws CryptoException;
}
```

## Security

This is not a software implementation, it's going to be as secure as the underlying hardware implementation is.

The full source code is not provided for legal reasons, but anyone is free to disassemble the .cap file to ensure no funny business is going on.

You can contact me at the email address attached to the PGP key for any question, clarification or auditing purpose.

### Hashes

The hashes in `hashes.signed.txt` are signed with the same key `F3A9F6CC8376D25400A271FB1BA818DB332833E4` that has been used for signing commits to this repo.

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mJMEakbsehMJKyQDAwIIAQENBAMEcEdS57x6G3rnb6W4eCzML8pMEvVOldUrTolC
hCvh2/ENSaJDEdPYh3zo7Qon+Zisilyvhg+/5T33V0tISESFAINpnO7QZF6YmEGd
aD7WHE9jJtjPZrvT3m8TACui3NTouS04OhDjrj08FmGudDDlrcmw0dBEko2xP/dK
sQ+U6Fe0FnN1dXQgPGNvbnRhY3RAc3V1dC5pbj6I0AQTEwoAOAULCQgHAgYVCgkI
CwIEFgIDAQIeAQIXgBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu4jAhsjAAoJ
EBuoGNszKDPkmA8B/REn4aGWw52AqLi7S6MYl2p0IpjrGTmzcFkMzqFRGKXs+NY0
ziOnYLnsvOSvFNRRPhBpgUkxaEJq9IHbhSxjkbICAJuTnGLkwdtEYS/QHC446jGI
3F92JjdxejlxB6kCnLTSJD619NzwzvlYocUuB/2F7Wk3r54pmKsMfmBYxBgaT724
lwRqRux6EgkrJAMDAggBAQ0EAwSjbEbzl4+I8WU5oM31phzOiAFQHztbD2WJOOss
/l2uJLeMGC5BdisJWwSng3gNUqsYRV9fx/iEssZZxXdLbdU7pfcZEh2U9Xmo+IoH
iqORr7dB/Nhhuaoxhe6BmJ5qhe0KyysD23upuleEQEZGJTH5RaVR7JtdrQanxJxq
XwZxoQMBCgmIuAQYEwoAIBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu7/AhsM
AAoJEBuoGNszKDPkxYAB/AvHbO+IqY5h0wjNimmeLmDksl27pfO1A2iRJ3BHYI+Y
3ecBXoQmPAY2iCFMW2xaEib9lWF8t6O6UaYu2BaSqFQB/A99fYb4L1NO9MRlGthl
yXoxFrRfkurIl7vwv0q+UIwciCRqf2IBdZNbnvQSw44FvioVO8VGPI4MffOrseHe
uj+4lwRqRux6EgkrJAMDAggBAQ0EAwSjeuaiJ/xsiMMMo78NHxhpNVOLUzWWgoG+
V97L2Fd52l9nRwz//leVesw1rACbdaH7TPqRI4S8LcjtwLT/zwEZR2PYsnuer43r
WBIBopsjY+gK1//IAtUPfdomyOJf05gQ+k6YcTQhYyuUTI/nx6y71CeQ4Y8HRbj7
TVvmqv8DugMBCgmIuAQYEwoAIBYhBPOp9syDdtJUAKJx+xuoGNszKDPkBQJqRu4z
AhsMAAoJEBuoGNszKDPklhkB/iNP3a9Pu3E1vlyRQUFM31FJm0Zu+jFw8LJf+dtp
TxvAz03cYj/COyKfHV6lmMiM3Ya1XsvgC4W+nBeD5SRI0UUB/iABB6/4+7a5Tqra
QKORAuuSffz1zwx7VkQYcc8dmCJ027yHe6MB7g8h6xva6aWPA0DXvApVP4FoY3cQ
n7BSsog=
=l2Qo
-----END PGP PUBLIC KEY BLOCK-----
```
