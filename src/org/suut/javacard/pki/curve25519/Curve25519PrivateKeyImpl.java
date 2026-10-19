package org.suut.javacard.pki.curve25519;

import javacard.security.CryptoException;

import jopx.JcopxPrivateKey;

/**
 * Private key implementation backed by the JCOPX key object.
 *
 * <p>Private key material (an EdDSA seed or an X25519 scalar) is used as-is, so the accessors
 * delegate directly to the JCOPX key without any byte-order conversion.
 */
final class Curve25519PrivateKeyImpl implements Curve25519PrivateKey {

    /** JCOPX key object. Package-private so that the builders and operations can use it. */
    final JcopxPrivateKey key;

    Curve25519PrivateKeyImpl(JcopxPrivateKey key) {
        this.key = key;
    }

    public short getS(byte[] buffer, short offset) throws CryptoException {
        return key.exportKey(buffer, offset);
    }

    public void setS(byte[] buffer, short offset, short length) throws CryptoException {
        key.importKey(buffer, offset, length);
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
