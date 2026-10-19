package jopx;

/**
 * Compile-time stand-in for the JCOPX (NXP JCOP eXtended) private key interface.
 *
 * <p><b>This package is a build-time placeholder only. It must never be installed on a card:</b>
 * a card that really exposes JCOPX already provides these classes in ROM. Installing this stub
 * would shadow them and every operation would then run against the methods below, which do
 * nothing.
 *
 * <p>The real class and method names are not recoverable: a CAP file only stores the
 * (package token, class token, method token) triple for external references, never the names.
 * The names used here are therefore arbitrary; what has to match the card is the token layout,
 * which is imposed by {@code tools/ExpPatch.java} (see {@code docs/RECONSTRUCTION.md}).
 */
public interface JcopxPrivateKey {

    public void clearKey();

    public short getSize();

    public byte getType();

    public boolean isInitialized();

    public byte getKeyMemoryType();

    public void importKey(byte[] buffer, short offset, short length);

    public short exportKey(byte[] buffer, short offset);
}
