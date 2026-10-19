package org.suut.javacard.pki.curve25519;

import javacard.framework.JCSystem;
import javacard.framework.TransactionException;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

import jopx.JcopxCurve25519;

/**
 * Class for X25519 key agreement.
 */
public final class Curve25519KeyAgreement {

    /**
     * JCOPX output buffer. It is transient so that the shared secret does not linger in persistent
     * memory.
     */
    private final byte[] buf;

    /**
     * Constructor for the key agreement object.
     *
     * <p>The constructor allocates a {@code CLEAR_ON_DESELECT} buffer in order to reverse the bytes
     * into the usual little-endian format specified in RFC 7748.
     */
    public Curve25519KeyAgreement() {
        buf = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * X25519 key agreement.
     *
     * @param privateKey the local private key
     * @param publicKey the remote public key
     * @param outBuff the buffer into which to write the shared secret
     * @param outOffset the offset in {@code outBuff} at which to write the shared secret
     * @return the length of the shared secret (always 32)
     * @throws javacard.security.CryptoException with reason
     *         {@code CryptoException.ILLEGAL_VALUE} if the keys are not Curve25519 keys or the
     *         underlying implementation does not return 32 bytes
     */
    public short keyExchange(PrivateKey privateKey, PublicKey publicKey, byte[] outBuff,
                             short outOffset) throws CryptoException {
        short length = JcopxCurve25519.keyAgreement(
                ((Curve25519PrivateKeyImpl) privateKey).key,
                ((Curve25519PublicKeyImpl) publicKey).key,
                (byte) 0xA4, buf, (short) 0);
        if (length != 32) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        try {
            JCSystem.beginTransaction();
            for (short i = 0; i < 32; i++) {
                outBuff[(short) (outOffset + 31 - i)] = buf[i];
            }
            Util.arrayFillNonAtomic(buf, (short) 0, (short) 32, (byte) 0);
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
}
