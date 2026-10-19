package org.suut.javacard.pki.curve25519;

import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.PrivateKey;
import javacard.security.PublicKey;

import jopx.JcopxKeyFactory;
import jopx.JcopxPrivateKey;
import jopx.JcopxPublicKey;

/**
 * Class for making and generating Curve25519 keys.
 */
public final class Curve25519KeyBuilder {

    /**
     * Algorithm type for private EdDSA keys.
     */
    public static final byte ALG_TYPE_EDDSA_PRIVATE = -127;
    /**
     * Algorithm type for public EdDSA keys.
     */
    public static final byte ALG_TYPE_EDDSA_PUBLIC = -128;
    /**
     * Algorithm type for private X25519 keys.
     */
    public static final byte ALG_TYPE_X25519_PRIVATE = -125;
    /**
     * Algorithm type for public X25519 keys.
     */
    public static final byte ALG_TYPE_X25519_PUBLIC = -126;

    private Curve25519KeyBuilder() {
    }

    /**
     * Builds an empty Curve25519 key.
     *
     * @param algo one of the {@code ALG_TYPE_*} constants
     * @param memoryType one of the {@code JCSystem.MEMORY_TYPE_*} constants
     * @return the key instance, to be cast to {@link Curve25519PrivateKey} or
     *         {@link Curve25519PublicKey}
     * @throws javacard.security.CryptoException with reason
     *         {@code CryptoException.NO_SUCH_ALGORITHM} if {@code algo} is not one of the
     *         {@code ALG_TYPE_*} constants
     */
    public static Key buildKey(byte algo, byte memoryType) throws CryptoException {
        switch (algo) {
            case ALG_TYPE_EDDSA_PRIVATE:
            case ALG_TYPE_X25519_PRIVATE:
                return new Curve25519PrivateKeyImpl(
                        (JcopxPrivateKey) JcopxKeyFactory.createKey(algo, memoryType));
            case ALG_TYPE_EDDSA_PUBLIC:
            case ALG_TYPE_X25519_PUBLIC:
                return new Curve25519PublicKeyImpl(
                        (JcopxPublicKey) JcopxKeyFactory.createKey(algo, memoryType));
            default:
                CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
                return null;
        }
    }

    /**
     * Generates or regenerates a key pair.
     *
     * @param privateKey an instance of {@link Curve25519PrivateKey}
     * @param publicKey an instance of {@link Curve25519PublicKey}
     * @throws javacard.security.CryptoException with reason
     *         {@code CryptoException.ILLEGAL_VALUE} if the provided keys do not have the correct
     *         type
     */
    public static void genKeyPair(PrivateKey privateKey, PublicKey publicKey) throws CryptoException {
        JcopxKeyFactory.genKeyPair(
                ((Curve25519PrivateKeyImpl) privateKey).key,
                ((Curve25519PublicKeyImpl) publicKey).key);
    }
}
