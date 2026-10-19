package org.suut.javacard.pki.curve25519;

import javacard.security.CryptoException;
import javacard.security.PublicKey;

/**
 * Interface for public Curve25519 keys.
 *
 * <p>Public keys are 32-byte encoded points in the little-endian format of RFC 7748 and RFC 8032.
 * The underlying JCOPX representation is big-endian, so both accessors reverse the bytes.
 */
public interface Curve25519PublicKey extends PublicKey, Curve25519Key {

    /**
     * Reads the public key into a buffer.
     *
     * @param buffer the buffer in which to write the public key
     * @param offset the offset in {@code buffer} at which to start writing
     * @return the length of data written to the buffer (always 32)
     * @throws java.lang.NullPointerException if {@code buffer} is null
     * @throws javacard.security.CryptoException with reason {@code CryptoException.ILLEGAL_VALUE}
     *         if the size of key is not supported (i.e. different than 32)
     */
    public short getW(byte[] buffer, short offset) throws CryptoException;

    /**
     * Sets the public key from a buffer.
     *
     * @param buffer the buffer from which to read the new public key
     * @param offset the offset in {@code buffer} from which to start reading
     * @param length the length of the new public key (must be 32)
     * @throws java.lang.NullPointerException if {@code buffer} is null
     * @throws java.lang.ArrayIndexOutOfBoundsException if {@code buffer} is smaller than 32 bytes
     * @throws javacard.security.CryptoException with reason {@code CryptoException.UNINITIALIZED_KEY}
     *         if the key has not been initialized
     */
    public void setW(byte[] buffer, short offset, short length) throws CryptoException;
}
