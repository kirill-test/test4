package com.example.sqli;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

public class Main {

    private static final String JDBC_URL =
            "jdbc:h2:mem:demo;DB_CLOSE_DELAY=-1;MODE=MySQL";

    private static final String PAGE_STYLE =
            "<style>body{font-family:sans-serif;max-width:680px;margin:2em auto;padding:0 1em}"
            + "a{color:#06c;text-decoration:none}a:hover{text-decoration:underline}"
            + "li{margin:.4em 0}"
            + "pre{background:#f4f4f4;padding:.6em;border-radius:6px;overflow:auto}"
            + "input[type=text]{padding:.4em;width:60%}"
            + ".warn{background:#fee;border:1px solid #f99;padding:.6em;border-radius:6px}"
            + ".err{color:#900;background:#fee;border:1px solid #f99;padding:.6em;border-radius:6px}"
            + "</style>";

    public static void main(String[] args) throws Exception {
        initDb();

        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new IndexHandler());
        server.createContext("/article", new ArticleHandler());
        server.createContext("/search", new SearchHandler());
        server.setExecutor(null);
        server.start();

        System.out.println("Vulnerability demo running at http://localhost:" + port + "/");
        System.out.println("  Normal article:   http://localhost:" + port + "/article?id=1");
        System.out.println("  SQLi (UNION):     http://localhost:" + port
                + "/article?id=0%20UNION%20SELECT%20id,%20username,%20password%20FROM%20users");
        System.out.println("  Reflected XSS:    http://localhost:" + port
                + "/search?q=%3Cscript%3Ealert(%27XSS%27)%3C/script%3E");
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(JDBC_URL, "sa", "");
    }

    private static void initDb() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE articles ("
                    + "  id INT PRIMARY KEY,"
                    + "  title VARCHAR(255),"
                    + "  body  VARCHAR(2000))");

            s.execute("INSERT INTO articles VALUES "
                    + "(1, 'Welcome',     'This is the first article in our tiny CMS.'),"
                    + "(2, 'Second post', 'Another article about something interesting.'),"
                    + "(3, 'Third post',  'Yet another article. SQL is fun.')");

            s.execute("CREATE TABLE users ("
                    + "  id INT PRIMARY KEY,"
                    + "  username VARCHAR(64),"
                    + "  password VARCHAR(64))");

            s.execute("INSERT INTO users VALUES "
                    + "(1, 'admin',  'hunter2-supersecret'),"
                    + "(2, 'alice',  'correct-horse-battery-staple'),"
                    + "(3, 'bob',    'p@ssw0rd!')");
        }
    }

    static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            String articleList = "";
            try (Connection c = connect();
                 Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery("SELECT id, title FROM articles ORDER BY id")) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String title = escape(rs.getString("title"));
                    articleList = articleList
                            + "<li><a href='/article?id=" + id + "'>" + title + "</a></li>";
                }
            } catch (SQLException e) {
                articleList = "<li>DB error: " + escape(e.getMessage()) + "</li>";
            }

            String html = "<!doctype html><html><head><meta charset='utf-8'>"
                    + "<title>Tiny CMS</title>"
                    + PAGE_STYLE
                    + "</head><body>"
                    + "<h1>Tiny CMS</h1>"
                    + "<p class='warn'><strong>Vulnerability demo.</strong> "
                    + "The article page concatenates the <code>id</code> parameter into a SQL query (SQLi), "
                    + "and the search page reflects the <code>q</code> parameter into HTML without escaping (XSS). "
                    + "Do not use this code anywhere real.</p>"

                    + "<h2>Search</h2>"
                    + "<form action='/search' method='get'>"
                    + "<input type='text' name='q' placeholder='search articles...'>"
                    + "<button type='submit'>Go</button>"
                    + "</form>"

                    + "<h2>Articles</h2><ul>" + articleList + "</ul>"

                    + "<h2>Try SQL injection</h2>"
                    + "<ul>"
                    + "<li><a href=\"/article?id=1\">Normal request: id=1</a></li>"
                    + "<li><a href=\"/article?id=0 UNION SELECT id, username, password FROM users\">"
                    + "UNION-based injection: leak users table (username as title, password as body)</a></li>"
                    + "<li><a href=\"/article?id=1 OR 1=1\">Boolean injection: id=1 OR 1=1</a></li>"
                    + "</ul>"

                    + "<h2>Try reflected XSS</h2>"
                    + "<ul>"
                    + "<li><a href=\"/search?q=hello\">Normal search: q=hello</a></li>"
                    + "<li><a href=\"/search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;\">"
                    + "Script tag payload</a></li>"
                    + "<li><a href=\"/search?q=&lt;img src=x onerror=alert('XSS-img')&gt;\">"
                    + "Image onerror payload</a></li>"
                    + "</ul>"

                    + "</body></html>";

            send(ex, 200, html);
        }
    }

    static class ArticleHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Map<String, String> q = parseQuery(ex.getRequestURI().getRawQuery());
            String id = q.getOrDefault("id", "");

            // !!! VULNERABLE: user input concatenated directly into SQL. !!!
            // Demonstration only. Real code MUST use PreparedStatement with parameters.
            String sql = "SELECT id, title, body FROM articles WHERE id = " + id;

            String body = "";
            try (Connection c = connect();
                 Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery(sql)) {

                boolean any = false;
                while (rs.next()) {
                    any = true;
                    body = body
                            + "<article>"
                            + "<h1>" + escape(rs.getString(2)) + "</h1>"
                            + "<p>" + escape(rs.getString(3)) + "</p>"
                            + "<p><small>id = " + escape(rs.getString(1)) + "</small></p>"
                            + "</article><hr>";
                }
                if (!any) {
                    body = "<p>No article found.</p>";
                }
            } catch (SQLException e) {
                body = "<p class='err'><strong>SQL error:</strong> " + escape(e.getMessage()) + "</p>";
            }

            String html = "<!doctype html><html><head><meta charset='utf-8'>"
                    + "<title>Article</title>"
                    + PAGE_STYLE
                    + "</head><body>"
                    + "<p><a href='/'>&larr; back</a></p>"
                    + "<h3>Executed SQL</h3>"
                    + "<pre>" + escape(sql) + "</pre>"
                    + body
                    + "</body></html>";

            send(ex, 200, html);
        }
    }

    static class SearchHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            Map<String, String> params = parseQuery(ex.getRequestURI().getRawQuery());
            String q = params.getOrDefault("q", "");

            String matches = "";
            // The search itself uses a PreparedStatement, so it is NOT SQL-injectable.
            // The vulnerability is below: q is reflected into HTML without escaping.
            try (Connection c = connect();
                 var ps = c.prepareStatement(
                         "SELECT id, title FROM articles WHERE LOWER(title) LIKE ? ORDER BY id")) {
                ps.setString(1, "%" + q.toLowerCase() + "%");
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        matches = matches
                                + "<li><a href='/article?id=" + rs.getInt("id") + "'>"
                                + escape(rs.getString("title")) + "</a></li>";
                    }
                }
            } catch (SQLException e) {
                matches = "<li class='err'>DB error: " + escape(e.getMessage()) + "</li>";
            }
            if (matches.isEmpty()) {
                matches = "<li>(no matches)</li>";
            }

            // !!! VULNERABLE: q is written into HTML without escaping (reflected XSS). !!!
            // Demonstration only. Real code MUST HTML-escape user input before rendering.
            String html = "<!doctype html><html><head><meta charset='utf-8'>"
                    + "<title>Search</title>"
                    + PAGE_STYLE
                    + "</head><body>"
                    + "<p><a href='/'>&larr; back</a></p>"
                    + "<h1>Search results</h1>"
                    + "<p>You searched for: <b>" + q + "</b></p>"
                    + "<form action='/search' method='get'>"
                    + "<input type='text' name='q' value='" + q + "'>"
                    + "<button type='submit'>Go</button>"
                    + "</form>"
                    + "<ul>" + matches + "</ul>"
                    + "</body></html>";

            send(ex, 200, html);
        }
    }

    private static Map<String, String> parseQuery(String raw) {
        Map<String, String> out = new HashMap<>();
        if (raw == null || raw.isEmpty()) return out;
        for (String pair : raw.split("&")) {
            int eq = pair.indexOf('=');
            String k = eq < 0 ? pair : pair.substring(0, eq);
            String v = eq < 0 ? "" : pair.substring(eq + 1);
            out.put(URLDecoder.decode(k, StandardCharsets.UTF_8),
                    URLDecoder.decode(v, StandardCharsets.UTF_8));
        }
        return out;
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    private static void send(HttpExchange ex, int code, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
