import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.Comparator;

import com.sun.javacard.exportfile.EfClass;
import com.sun.javacard.exportfile.EfExportFile;
import com.sun.javacard.exportfile.EfMethod;

/**
 * Rewrites the class and method tokens of a single class in an export file.
 *
 * <p>Usage: {@code ExpRetoken <in.exp> <out.exp> <class name> <class token>
 * [<method name> <method descriptor> <method token>]...}</p>
 *
 * <p>Used by the on-card token probes: the JCOPX export file of an older card is not available, so
 * the only way to learn which (class token, method token) pairs exist is to compile a tiny CAP
 * against a synthetic export file and see whether the card accepts it.</p>
 */
public final class ExpRetoken {

    private ExpRetoken() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.err.println("usage: ExpRetoken <in.exp> <out.exp> <class name> <class token>"
                    + " [<method name> <method descriptor> <method token>]...");
            System.exit(2);
        }

        EfExportFile exportFile = new EfExportFile();
        exportFile.parse(new DataInputStream(new FileInputStream(args[0])));
        exportFile.resolve();

        EfClass target = findClass(exportFile, args[2]);
        int classToken = decode(args[3]);
        target.setClassToken(classToken);
        System.out.println("class " + args[2] + " -> token " + classToken);

        for (int i = 4; i + 2 < args.length; i += 3) {
            EfMethod method = findMethod(target, args[i], args[i + 1]);
            if (method == null) {
                System.err.println("error: no method " + args[i] + args[i + 1] + " in " + args[2]);
                System.exit(1);
            }
            int token = decode(args[i + 2]);
            method.setMethodToken(token);
            System.out.println("  method " + args[i] + args[i + 1] + " -> token " + token);
        }

        // The export file is written in array order, so keep it sorted by token.
        Arrays.sort(exportFile.getClasses(), Comparator.comparingInt(EfClass::getClassToken));

        try (DataOutputStream out = new DataOutputStream(new FileOutputStream(args[1]))) {
            exportFile.toBinary(out);
        }
        System.out.println("wrote " + args[1]);
    }

    private static int decode(String value) {
        if (value.startsWith("0x") || value.startsWith("0X")) {
            return Integer.parseInt(value.substring(2), 16);
        }
        return Integer.parseInt(value);
    }

    private static EfClass findClass(EfExportFile exportFile, String name) {
        for (EfClass cls : exportFile.getClasses()) {
            if (cls.getClassName().equals(name)) {
                return cls;
            }
        }
        System.err.println("error: class " + name + " not found");
        System.exit(1);
        return null;
    }

    private static EfMethod findMethod(EfClass cls, String name, String descriptor) {
        for (EfMethod method : cls.getMethods()) {
            if (method.getMethodName().equals(name) && method.getMethodDescriptor().equals(descriptor)) {
                return method;
            }
        }
        return null;
    }
}
