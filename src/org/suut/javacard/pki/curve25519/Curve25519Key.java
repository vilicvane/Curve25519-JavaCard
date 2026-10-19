package org.suut.javacard.pki.curve25519;

/**
 * Common interface of the Curve25519 key types provided by this package.
 */
public interface Curve25519Key {

    /**
     * @return one of the {@code JCSystem.MEMORY_TYPE_*} constants
     */
    public byte getKeyMemoryType();
}
