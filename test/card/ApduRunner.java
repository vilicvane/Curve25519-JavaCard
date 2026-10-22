import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * Keeps one PC/SC session open and forwards raw APDUs from standard input.
 *
 * <p>The applet is selected once, then every input line is one hex encoded APDU (whitespace is
 * ignored). For every line one result line is written to standard output:</p>
 *
 * <pre>
 * DATA=&lt;hex&gt; SW=&lt;sw&gt;
 * </pre>
 *
 * <p>Response chaining ({@code 61 XX}) and {@code 6C XX} length corrections are handled here so
 * that the caller always sees the complete response.</p>
 *
 * <p>This is used instead of {@code gp -a} because GlobalPlatformPro opens a fresh session for
 * every invocation, and an APDU is only meaningful while the applet stays selected.</p>
 *
 * <p>Usage: {@code java ApduRunner <applet AID as hex>}; the first present terminal is used.</p>
 */
public final class ApduRunner {

    private ApduRunner() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: ApduRunner <applet aid hex>");
            System.exit(2);
        }

        byte[] aid = decode(args[0]);
        CardTerminal terminal = firstPresentTerminal();
        System.err.println("# terminal: " + terminal.getName());

        Card card = terminal.connect("*");
        try {
            System.err.println("# atr: " + encode(card.getATR().getBytes()));
            CardChannel channel = card.getBasicChannel();

            ResponseAPDU selected = channel.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, aid));
            if (selected.getSW() != 0x9000) {
                System.err.println("# select failed, SW=" + word(selected.getSW()));
                System.exit(3);
            }
            System.err.println("# selected " + encode(aid));

            PrintStream out = new PrintStream(System.out, true, "US-ASCII");
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in, "US-ASCII"));
            String line;
            while ((line = in.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                byte[] command = decode(line);
                ResponseAPDU response = transmit(channel, command);
                out.println("DATA=" + encode(response.getData()) + " SW=" + word(response.getSW()));
            }
            out.flush();
        } finally {
            card.disconnect(false);
        }
    }

    private static ResponseAPDU transmit(CardChannel channel, byte[] command) throws CardException {
        ResponseAPDU response = channel.transmit(new CommandAPDU(command));
        List<Byte> data = new ArrayList<Byte>();
        for (byte b : response.getData()) {
            data.add(Byte.valueOf(b));
        }
        int sw = response.getSW();

        while (true) {
            if ((sw >> 8) == 0x61) {
                int remaining = sw & 0xFF;
                ResponseAPDU next = channel.transmit(
                        new CommandAPDU(0x00, 0xC0, 0x00, 0x00, remaining == 0 ? 256 : remaining));
                for (byte b : next.getData()) {
                    data.add(Byte.valueOf(b));
                }
                sw = next.getSW();
            } else if ((sw >> 8) == 0x6C) {
                byte[] corrected = command.clone();
                corrected[corrected.length - 1] = (byte) (sw & 0xFF);
                response = channel.transmit(new CommandAPDU(corrected));
                data.clear();
                for (byte b : response.getData()) {
                    data.add(Byte.valueOf(b));
                }
                sw = response.getSW();
            } else {
                break;
            }
        }

        byte[] bytes = new byte[data.size()];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = data.get(i).byteValue();
        }
        return new ResponseAPDU(append(bytes, (byte) (sw >> 8), (byte) sw));
    }

    private static byte[] append(byte[] data, byte sw1, byte sw2) {
        byte[] result = new byte[data.length + 2];
        System.arraycopy(data, 0, result, 0, data.length);
        result[data.length] = sw1;
        result[data.length + 1] = sw2;
        return result;
    }

    private static CardTerminal firstPresentTerminal() throws CardException {
        TerminalFactory factory = TerminalFactory.getDefault();
        for (CardTerminal terminal : factory.terminals().list()) {
            if (terminal.isCardPresent()) {
                return terminal;
            }
        }
        System.err.println("error: no card present in any terminal");
        System.exit(4);
        return null;
    }

    private static String word(int sw) {
        return String.format("%04X", Integer.valueOf(sw));
    }

    private static String encode(byte[] bytes) {
        StringBuilder builder = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            builder.append(Character.forDigit((b >> 4) & 0xF, 16));
            builder.append(Character.forDigit(b & 0xF, 16));
        }
        return builder.toString().toUpperCase();
    }

    private static byte[] decode(String hex) {
        String clean = hex.replaceAll("[^0-9A-Fa-f]", "");
        if ((clean.length() & 1) != 0) {
            throw new IllegalArgumentException("odd number of hex digits: " + hex);
        }
        byte[] bytes = new byte[clean.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
}
