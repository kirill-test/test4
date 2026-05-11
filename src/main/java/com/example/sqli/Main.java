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

    public static void main(String[] args) throws Exception {
        initDb();

        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/", new IndexHandler());
        server.createContext("/article", new ArticleHandler());
        server.setExecutor(null);
        server.start();

        System.out.println("SQLi demo running at http://localhost:" + port + "/");
        System.out.println("Try a normal article:  http://localhost:" + port + "/article?id=1");
        System.out.println("Try an injection:      http://localhost:" + port
                + "/article?id=0%20UNION%20SELECT%20id,%20username,%20password%20FROM%20users");
    }

    private static Connection connect() throws SQLException {
        return DriverManager.getConnection(JDBC_URL, "sa", "");
    }

    private static void initDb() throws SQLException {
        try (Connection c = connect(); Statement s = c.createStatement()) {
            s.execute("CREATE TABLE articles (" +
                    "  id INT PRIMARY KEY," +
                    "  title VARCHAR(255)," +
                    "  body  VARCHAR(2000))");

            s.execute("INSERT INTO articles VALUES " +
                    "(1, 'Welcome',     'This is the first article in our tiny CMS.')," +
                    "(2, 'Second post', 'Another article about something interesting.')," +
                    "(3, 'Third post',  'Yet another article. SQL is fun.')");

            s.execute("CREATE TABLE users (" +
                    "  id INT PRIMARY KEY," +
                    "  username VARCHAR(64)," +
                    "  password VARCHAR(64))");

            s.execute("INSERT INTO users VALUES " +
                    "(1, 'admin',  'hunter2-supersecret')," +
                    "(2, 'alice',  'correct-horse-battery-staple')," +
                    "(3, 'bob',    'p@ssw0rd!')");
        }
    }

    static class IndexHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            StringBuilder html = new StringBuilder();
            html.append("<!doctype html><html><head><meta charset='utf-8'>")
                .append("<title>Tiny CMS</title>")
                .append("<style>body{font-family:sans-serif;max-width:680px;margin:2em auto;padding:0 1em}")
                .append("a{color:#06c;text-decoration:none}a:hover{text-decoration:underline}")
                .append("li{margin:.4em 0}.warn{background:#fee;border:1px solid #f99;padding:.6em;border-radius:6px}</style>")
                .append("</head><body>")
                .append("<h1>Tiny CMS</h1>")
                .append("<p class='warn'><strong>SQL Injection demo.</strong> ")
                .append("The article page concatenates the <code>id</code> parameter into a SQL query. Do not use this code anywhere real.</p>")
                .append("<h2>Articles</h2><ul>");

            try (Connection c = connect();
                 Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery("SELECT id, title FROM articles ORDER BY id")) {
                while (rs.next()) {
                    int id = rs.getInt("id");
                    String title = escape(rs.getString("title"));
                    html.append("<li><a href='/article?id=").append(id).append("'>")
                        .append(title).append("</a></li>");
                }
            } catch (SQLException e) {
                html.append("<li>DB error: ").append(escape(e.getMessage())).append("</li>");
            }

            html.append("</ul>")
                .append("<h2>Try the vulnerability</h2>")
                .append("<ul>")
                .append("<li><a href=\"/article?id=1\">Normal request: id=1</a></li>")
                .append("<li><a href=\"/article?id=0 UNION SELECT id, username, password FROM users\">")
                .append("UNION-based injection: leak users table (username shown as title, password as body)</a></li>")
                .append("<li><a href=\"/article?id=1 OR 1=1\">Boolean injection: id=1 OR 1=1</a></li>")
                .append("</ul>")
                .append("</body></html>");

            send(ex, 200, html.toString());
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

            StringBuilder html = new StringBuilder();
            html.append("<!doctype html><html><head><meta charset='utf-8'>")
                .append("<title>Article</title>")
                .append("<style>body{font-family:sans-serif;max-width:680px;margin:2em auto;padding:0 1em}")
                .append("pre{background:#f4f4f4;padding:.6em;border-radius:6px;overflow:auto}")
                .append(".err{color:#900;background:#fee;border:1px solid #f99;padding:.6em;border-radius:6px}</style>")
                .append("</head><body>")
                .append("<p><a href='/'>&larr; back to articles</a></p>")
                .append("<h3>Executed SQL</h3>")
                .append("<pre>").append(escape(sql)).append("</pre>");

            try (Connection c = connect();
                 Statement s = c.createStatement();
                 ResultSet rs = s.executeQuery(sql)) {

                boolean any = false;
                while (rs.next()) {
                    any = true;
                    html.append("<article>")
                        .append("<h1>").append(escape(rs.getString(2))).append("</h1>")
                        .append("<p>").append(escape(rs.getString(3))).append("</p>")
                        .append("<p><small>id = ").append(escape(rs.getString(1))).append("</small></p>")
                        .append("</article><hr>");
                }
                if (!any) {
                    html.append("<p>No article found.</p>");
                }
            } catch (SQLException e) {
                html.append("<p class='err'><strong>SQL error:</strong> ")
                    .append(escape(e.getMessage())).append("</p>");
            }

            html.append("</body></html>");
            send(ex, 200, html.toString());
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
