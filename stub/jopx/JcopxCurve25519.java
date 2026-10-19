package jopx;

/**
 * Compile-time stand-in for the JCOPX (NXP JCOP eXtended) Curve25519 operations.
 *
 * <p><b>This package is a build-time placeholder only. It must never be installed on a card</b>
 * (see {@link JcopxPrivateKey} for the rationale).
 *
 * <p>The methods below reproduce the calls that the original {@code Curve25519.cap} makes into
 * JCOPX. Their signatures are reconstructed from the bytecode of the original library; the names
 * are arbitrary because the CAP file does not record them. The magic {@code type} bytes
 * ({@code 0xA3} for EdDSA, {@code 0xA4} for X25519) and the JCOPX return conventions
 * (64 bytes for a signature, 32 for a shared secret, {@code 0x5A5A} for a valid signature) are
 * taken verbatim from the original bytecode.
 *
 * <p>The converter insists that an exported class has consecutive method tokens starting at 0, so
 * the class is padded with {@code m0}, {@code m1} and {@code m4}..{@code m12} to make
 * {@code sign}, {@code verify} and {@code keyAgreement} land on tokens 2, 3 and 13 after
 * {@code tools/ExpPatch} has rewritten them. The padding is never called.
 */
public final class JcopxCurve25519 {

    private JcopxCurve25519() {
    }

    public static short m0() {
        return 0;
    }

    public static short m1() {
        return 0;
    }

    /**
     * Ed25519 signature.
     *
     * @return the signature length, 64 on success
     */
    public static short sign(JcopxPrivateKey key, byte type, byte[] hash, short hashOffset,
                             short hashLength, byte[] out, short outOffset) {
        return 0;
    }

    /**
     * Ed25519 verification.
     *
     * @return {@code 0x5A5A} if the signature is valid
     */
    public static short verify(JcopxPublicKey key, byte type, byte[] hash, short hashOffset,
                               short hashLength, byte[] signature, short signatureOffset,
                               short signatureLength) {
        return 0;
    }

    public static short m4() {
        return 0;
    }

    public static short m5() {
        return 0;
    }

    public static short m6() {
        return 0;
    }

    public static short m7() {
        return 0;
    }

    public static short m8() {
        return 0;
    }

    public static short m9() {
        return 0;
    }

    public static short m10() {
        return 0;
    }

    public static short m11() {
        return 0;
    }

    public static short m12() {
        return 0;
    }

    /**
     * X25519 key agreement.
     *
     * @return the shared secret length, 32 on success
     */
    public static short keyAgreement(JcopxPrivateKey privateKey, JcopxPublicKey publicKey,
                                     byte type, byte[] out, short outOffset) {
        return 0;
    }
}
