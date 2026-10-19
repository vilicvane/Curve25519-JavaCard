package org.suut.javacard.pki.curve25519;

import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

import jopx.JcopxCurve25519;

/**
 * Class for making and verifying Ed25519 signatures.
 */
public final class Curve25519Signature {

    /**
     * JCOPX output buffer. It is transient so that signature material does not linger in
     * persistent memory.
     */
    private final byte[] buf;

    /**
     * Constructor for the EdDSA signature object.
     *
     * <p>The constructor allocates {@code CLEAR_ON_DESELECT} storage to be able to reverse the
     * signature r and s components to match the little-endian format specified in RFC 8032.
     */
    public Curve25519Signature() {
        buf = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Sign with EdDSA on Curve25519.
     *
     * <p>This uses the Ed25519 algorithm specified in RFC 8032.
     *
     * @param privateKey the private key used for signing
     * @param inBuff the data to sign
     * @param inOffset the offset in {@code inBuff} at which to start reading the data
     * @param inLength the length of data to sign
     * @param outBuff the buffer in which to write the signature
     * @param outOffset the offset into {@code outBuff} at which to write the signature
     * @return the length of the signature written to {@code outBuff} (64)
     * @throws javacard.security.CryptoException with reason
     *         {@code CryptoException.ILLEGAL_VALUE} if the key is not a {@link Curve25519PrivateKey}
     *         or the underlying implementation does not return 64 bytes
     */
    public short sign(PrivateKey privateKey, byte[] inBuff, short inOffset, short inLength,
                      byte[] outBuff, short outOffset) throws CryptoException {
        if (!(privateKey instanceof Curve25519PrivateKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        short length = JcopxCurve25519.sign(
                ((Curve25519PrivateKeyImpl) privateKey).key,
                (byte) 0xA3, inBuff, inOffset, inLength, buf, (short) 0);
        if (length != 64) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        try {
            JCSystem.beginTransaction();
            for (short i = 0; i < 32; i++) {
                outBuff[(short) (outOffset + 31 - i)] = buf[i];
                outBuff[(short) (outOffset + 63 - i)] = buf[(short) (32 + i)];
            }
            JCSystem.commitTransaction();
        } catch (Throwable e) {
            try {
                JCSystem.abortTransaction();
            } catch (TransactionException alreadyAborted) {
                // A failed commit has already rolled the transaction back.
            }
            throw e;
        }
        return length;
    }

    /**
     * Verify an EdDSA signature on Curve25519.
     *
     * <p>This uses the Ed25519 algorithm specified in RFC 8032.
     *
     * @param publicKey the public key used for verification
     * @param inBuff the data for which the signature was made
     * @param inOffset the offset in {@code inBuff} at which to start reading the data
     * @param inLength the length of data to sign
     * @param signatureBuff the buffer from which to read the signature
     * @param signatureOffset the offset into {@code signatureBuff} from which to read the signature
     * @param signatureLength the length of the signature (must be 64)
     * @return {@code true} if the signature matches, {@code false} otherwise
     * @throws javacard.security.CryptoException with reason
     *         {@code CryptoException.ILLEGAL_VALUE} if the key is not a
     *         {@link Curve25519PublicKey}
     */
    public boolean verify(PublicKey publicKey, byte[] inBuff, short inOffset, short inLength,
                          byte[] signatureBuff, short signatureOffset, short signatureLength)
            throws CryptoException {
        if (!(publicKey instanceof Curve25519PublicKeyImpl)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (signatureLength != 64) {
            return false;
        }
        for (short i = 0; i < 32; i++) {
            buf[i] = signatureBuff[(short) (signatureOffset + 31 - i)];
            buf[(short) (32 + i)] = signatureBuff[(short) (signatureOffset + 63 - i)];
        }
        short result = JcopxCurve25519.verify(
                ((Curve25519PublicKeyImpl) publicKey).key,
                (byte) 0xA3, inBuff, inOffset, inLength, buf, (short) 0, (short) 64);
        return result == (short) 0x5A5A;
    }
}
