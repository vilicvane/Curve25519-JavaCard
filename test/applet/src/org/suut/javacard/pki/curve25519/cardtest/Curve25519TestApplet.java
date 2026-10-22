package org.suut.javacard.pki.curve25519.cardtest;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

import org.suut.javacard.pki.curve25519.Curve25519KeyAgreement;
import org.suut.javacard.pki.curve25519.Curve25519KeyBuilder;
import org.suut.javacard.pki.curve25519.Curve25519PrivateKey;
import org.suut.javacard.pki.curve25519.Curve25519PublicKey;
import org.suut.javacard.pki.curve25519.Curve25519Signature;

/**
 * Test applet for the reconstructed {@code org.suut.javacard.pki.curve25519} package.
 *
 * <p>The applet owns one EdDSA key pair, one X25519 key pair and one extra X25519 public key that is
 * used as the remote party in a key exchange. Every command is deliberately small so that a host
 * side driver can compare each result against a software reference implementation.</p>
 *
 * <p>Commands (CLA is ignored, data is always at {@code ISO7816.OFFSET_CDATA}):</p>
 *
 * <pre>
 * 00 01 P1 --   generate a key pair, returns the 32 byte public key
 *               P1=00 EdDSA, P1=01 X25519
 * 00 10 P1 --   read a public key, returns 32 bytes (P1=00 EdDSA, P1=01 X25519)
 * 00 11 P1 --   read a private key, returns 32 bytes (P1=00 EdDSA, P1=01 X25519)
 * 00 12 P1 32   write a public key (P1=00 EdDSA, P1=01 X25519)
 * 00 13 P1 32   write a private key (P1=00 EdDSA, P1=01 X25519)
 * 00 30 -- Lc   sign the Lc byte input, returns the 64 byte signature
 * 00 40 -- Lc   verify: input is hash (Lc-64 bytes) followed by a 64 byte signature,
 *               SW 9000 when valid, SW 6982 when invalid
 * 00 50 -- 32   X25519 key exchange with the supplied remote public key, returns 32 bytes
 * 00 60 --  0   diagnostics: 12 bytes (memory types, key sizes and initialised flags)
 * </pre>
 *
 * <p>Exceptions are mapped to status words so that a failure is visible instead of a plain 6F00:
 * {@code 6A00 + CryptoException.getReason()} for crypto failures, {@code 6B00 + index} for
 * unexpected runtime failures inside a command.</p>
 */
public final class Curve25519TestApplet extends Applet {

    private static final byte INS_GENERATE_PAIR = (byte) 0x01;
    private static final byte INS_GET_PUBLIC = (byte) 0x10;
    private static final byte INS_GET_PRIVATE = (byte) 0x11;
    private static final byte INS_SET_PUBLIC = (byte) 0x12;
    private static final byte INS_SET_PRIVATE = (byte) 0x13;
    private static final byte INS_SIGN = (byte) 0x30;
    private static final byte INS_VERIFY = (byte) 0x40;
    private static final byte INS_EXCHANGE = (byte) 0x50;
    private static final byte INS_INFO = (byte) 0x60;

    private static final byte P1_EDDSA = (byte) 0x00;
    private static final byte P1_X25519 = (byte) 0x01;

    private static final short KEY_LENGTH = (short) 32;
    private static final short SIGNATURE_LENGTH = (short) 64;

    private final Curve25519PrivateKey eddsaPrivate;
    private final Curve25519PublicKey eddsaPublic;
    private final Curve25519PrivateKey x25519Private;
    private final Curve25519PublicKey x25519Public;
    private final Curve25519PublicKey x25519Remote;
    private final Curve25519Signature signature;
    private final Curve25519KeyAgreement keyAgreement;

    /** Staging buffer for outputs, cleared on deselect like the library does internally. */
    private final byte[] scratch;

    private Curve25519TestApplet() {
        eddsaPrivate = (Curve25519PrivateKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_EDDSA_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
        eddsaPublic = (Curve25519PublicKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_EDDSA_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
        x25519Private = (Curve25519PrivateKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_X25519_PRIVATE, JCSystem.MEMORY_TYPE_PERSISTENT);
        x25519Public = (Curve25519PublicKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_PERSISTENT);
        x25519Remote = (Curve25519PublicKey) Curve25519KeyBuilder.buildKey(
                Curve25519KeyBuilder.ALG_TYPE_X25519_PUBLIC, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        signature = new Curve25519Signature();
        keyAgreement = new Curve25519KeyAgreement();
        scratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new Curve25519TestApplet().register();
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        short length = apdu.setIncomingAndReceive();

        try {
            switch (ins) {
            case INS_GENERATE_PAIR:
                generatePair(p1);
                sendPublic(apdu, p1);
                break;
            case INS_GET_PUBLIC:
                sendPublic(apdu, p1);
                break;
            case INS_GET_PRIVATE:
                sendPrivate(apdu, p1);
                break;
            case INS_SET_PUBLIC:
                setPublic(p1, buffer, length);
                break;
            case INS_SET_PRIVATE:
                setPrivate(p1, buffer, length);
                break;
            case INS_SIGN:
                sign(apdu, buffer, length);
                break;
            case INS_VERIFY:
                verify(apdu, buffer, length);
                break;
            case INS_EXCHANGE:
                exchange(apdu, buffer, length);
                break;
            case INS_INFO:
                sendInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (CryptoException e) {
            ISOException.throwIt((short) (0x6A00 + (short) e.getReason()));
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt((short) 0x6B01);
        } catch (NullPointerException e) {
            ISOException.throwIt((short) 0x6B02);
        } catch (SecurityException e) {
            ISOException.throwIt((short) 0x6B03);
        }
    }

    private void generatePair(byte p1) {
        if (p1 == P1_EDDSA) {
            Curve25519KeyBuilder.genKeyPair(eddsaPrivate, eddsaPublic);
        } else if (p1 == P1_X25519) {
            Curve25519KeyBuilder.genKeyPair(x25519Private, x25519Public);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void sendPublic(APDU apdu, byte p1) {
        byte[] buffer = apdu.getBuffer();
        short length;
        if (p1 == P1_EDDSA) {
            length = eddsaPublic.getW(buffer, (short) 0);
        } else if (p1 == P1_X25519) {
            length = x25519Public.getW(buffer, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        apdu.setOutgoingAndSend((short) 0, length);
    }

    private void sendPrivate(APDU apdu, byte p1) {
        byte[] buffer = apdu.getBuffer();
        short length;
        if (p1 == P1_EDDSA) {
            length = eddsaPrivate.getS(buffer, (short) 0);
        } else if (p1 == P1_X25519) {
            length = x25519Private.getS(buffer, (short) 0);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        apdu.setOutgoingAndSend((short) 0, length);
    }

    private void setPublic(byte p1, byte[] buffer, short length) {
        if (length != KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (p1 == P1_EDDSA) {
            eddsaPublic.setW(buffer, ISO7816.OFFSET_CDATA, KEY_LENGTH);
        } else if (p1 == P1_X25519) {
            x25519Public.setW(buffer, ISO7816.OFFSET_CDATA, KEY_LENGTH);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void setPrivate(byte p1, byte[] buffer, short length) {
        if (length != KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (p1 == P1_EDDSA) {
            eddsaPrivate.setS(buffer, ISO7816.OFFSET_CDATA, KEY_LENGTH);
        } else if (p1 == P1_X25519) {
            x25519Private.setS(buffer, ISO7816.OFFSET_CDATA, KEY_LENGTH);
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    private void sign(APDU apdu, byte[] buffer, short length) {
        short signatureLength = signature.sign(eddsaPrivate, buffer, ISO7816.OFFSET_CDATA, length,
                scratch, (short) 0);
        if (signatureLength != SIGNATURE_LENGTH) {
            ISOException.throwIt((short) 0x6C01);
        }
        Util.arrayCopyNonAtomic(scratch, (short) 0, buffer, (short) 0, signatureLength);
        apdu.setOutgoingAndSend((short) 0, signatureLength);
    }

    private void verify(APDU apdu, byte[] buffer, short length) {
        if (length <= SIGNATURE_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short hashLength = (short) (length - SIGNATURE_LENGTH);
        boolean valid = signature.verify(eddsaPublic, buffer, ISO7816.OFFSET_CDATA, hashLength,
                buffer, (short) (ISO7816.OFFSET_CDATA + hashLength), SIGNATURE_LENGTH);
        if (!valid) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void exchange(APDU apdu, byte[] buffer, short length) {
        if (length != KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        x25519Remote.setW(buffer, ISO7816.OFFSET_CDATA, KEY_LENGTH);
        short secretLength = keyAgreement.keyExchange(x25519Private, x25519Remote, scratch, (short) 0);
        if (secretLength != KEY_LENGTH) {
            ISOException.throwIt((short) 0x6C02);
        }
        Util.arrayCopyNonAtomic(scratch, (short) 0, buffer, (short) 0, secretLength);
        apdu.setOutgoingAndSend((short) 0, secretLength);
    }

    private void sendInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = eddsaPrivate.getKeyMemoryType();
        buffer[1] = eddsaPublic.getKeyMemoryType();
        buffer[2] = x25519Private.getKeyMemoryType();
        buffer[3] = x25519Public.getKeyMemoryType();
        buffer[4] = (byte) eddsaPrivate.getSize();
        buffer[5] = (byte) eddsaPublic.getSize();
        buffer[6] = (byte) x25519Private.getSize();
        buffer[7] = (byte) x25519Public.getSize();
        buffer[8] = (byte) (eddsaPrivate.isInitialized() ? 1 : 0);
        buffer[9] = (byte) (eddsaPublic.isInitialized() ? 1 : 0);
        buffer[10] = (byte) (x25519Private.isInitialized() ? 1 : 0);
        buffer[11] = (byte) (x25519Public.isInitialized() ? 1 : 0);
        apdu.setOutgoingAndSend((short) 0, (short) 12);
    }
}
