package org.suut.javacard.pki.curve25519;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;

import jopx.JcopxPublicKey;

/**
 * Public key implementation backed by the JCOPX key object.
 *
 * <p>JCOPX stores public keys in big-endian format, while this package exposes the little-endian
 * format of RFC 7748 and RFC 8032. Both accessors therefore reverse the 32 key bytes through a
 * transient buffer.
 */
final class Curve25519PublicKeyImpl implements Curve25519PublicKey {

    /** JCOPX key object. Package-private so that the builders and operations can use it. */
    final JcopxPublicKey key;

    /** Transient big-endian staging buffer for the 32 key bytes. */
    private final byte[] buf;

    Curve25519PublicKeyImpl(JcopxPublicKey key) {
        this.key = key;
        this.buf = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
    }

    public short getW(byte[] buffer, short offset) throws CryptoException {
        short length = key.exportKey(buf, (short) 0);
        if (length != 32) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        for (short i = 0; i < 32; i++) {
            buffer[(short) (offset + 31 - i)] = buf[i];
        }
        return length;
    }

    public void setW(byte[] buffer, short offset, short length) throws CryptoException {
        if (length != 32) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        for (short i = 0; i < 32; i++) {
            buf[i] = buffer[(short) (offset + 31 - i)];
        }
        key.importKey(buf, (short) 0, (short) 32);
    }

    public byte getKeyMemoryType() {
        return key.getKeyMemoryType();
    }

    public void clearKey() {
        key.clearKey();
    }

    public short getSize() {
        return key.getSize();
    }

    public byte getType() {
        return key.getType();
    }

    public boolean isInitialized() {
        return key.isInitialized();
    }
}
