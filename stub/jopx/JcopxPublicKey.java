package jopx;

/**
 * Compile-time stand-in for the JCOPX (NXP JCOP eXtended) public key interface.
 *
 * <p><b>This package is a build-time placeholder only. It must never be installed on a card</b>
 * (see {@link JcopxPrivateKey} for the rationale).
 */
public interface JcopxPublicKey {

    public void clearKey();

    public short getSize();

    public byte getType();

    public boolean isInitialized();

    public byte getKeyMemoryType();

    public void importKey(byte[] buffer, short offset, short length);

    public short exportKey(byte[] buffer, short offset);
}
