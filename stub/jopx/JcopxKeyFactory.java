package jopx;

/**
 * Compile-time stand-in for the JCOPX (NXP JCOP eXtended) key factory and key pair generator.
 *
 * <p><b>This package is a build-time placeholder only. It must never be installed on a card</b>
 * (see {@link JcopxPrivateKey} for the rationale).
 *
 * <p>{@code m0} pads the class so that {@code createKey} and {@code genKeyPair} land on tokens 1
 * and 2 after {@code tools/ExpPatch} has rewritten them; the converter rejects gaps in the method
 * token space. The padding is never called.
 */
public final class JcopxKeyFactory {

    private JcopxKeyFactory() {
    }

    public static short m0() {
        return 0;
    }

    /**
     * Creates an empty JCOPX key object.
     *
     * <p>The result has to be cast to {@link JcopxPrivateKey} or {@link JcopxPublicKey} depending
     * on {@code algorithm}; this is exactly what the original library does.
     *
     * @param algorithm one of the {@code Curve25519KeyBuilder.ALG_TYPE_*} constants
     * @param memoryType one of the {@code JCSystem.MEMORY_TYPE_*} constants
     */
    public static Object createKey(byte algorithm, byte memoryType) {
        return null;
    }

    /**
     * Generates or regenerates the key pair held by the two key objects.
     */
    public static void genKeyPair(JcopxPrivateKey privateKey, JcopxPublicKey publicKey) {
    }
}
