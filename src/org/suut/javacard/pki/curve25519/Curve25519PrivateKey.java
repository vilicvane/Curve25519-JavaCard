package org.suut.javacard.pki.curve25519;

import javacard.security.CryptoException;
import javacard.security.PrivateKey;

/**
 * Interface for private Curve25519 keys.
 *
 * <p>The key material is a 32-byte value: a seed for EdDSA or a scalar for X25519. Both are used
 * verbatim, without any byte-order conversion.
 */
public interface Curve25519PrivateKey extends PrivateKey, Curve25519Key {

    /**
     * Reads the private key into a buffer.
     *
     * @param buffer the buffer in which to write the private key
     * @param offset the offset in buffer at which to start writing
     * @return the length of data written to buffer (always 32)
     * @throws java.lang.NullPointerException if {@code buffer} is null
     * @throws javacard.security.CryptoException with reason {@code CryptoException.ILLEGAL_VALUE}
     *         if the size of the key is not supported (i.e. different than 32)
     */
    public short getS(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the private key from a buffer.
     *
     * @param buffer the buffer from which to read the new private key
     * @param offset the offset in buffer from which to start reading
     * @param length the length of the new private key (must be 32)
     * @throws java.lang.NullPointerException if {@code buffer} is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if {@code buffer} is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason {@code CryptoException.UNINITIALIZED_KEY}
     *         if the key has not been initialized
     */
    public void setS(byte[] buffer, short offset, short length) throws CryptoException;
}
