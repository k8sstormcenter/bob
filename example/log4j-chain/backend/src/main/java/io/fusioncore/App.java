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
 *
 * Reads postgres connection settings from env (POSTGRES_HOST, POSTGRES_USER,
 * POSTGRES_DB). Trust auth assumed.
 */
public class App {
    private static final Logger log = LogManager.getLogger(App.class);

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/api/products", new ProductHandler());
        s.createContext("/api/login", new LoginHandler());
        s.setExecutor(Executors.newFixedThreadPool(4));
        s.start();
        log.info("chain-backend started on port {}", port);
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
