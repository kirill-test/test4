# Web Vulnerability Demo (Java)

A minimal Java web app to demonstrate two common web vulnerabilities:
**SQL injection** and **reflected XSS**.
**Educational use only — the code is intentionally vulnerable. Never deploy this.**

## Stack

- Java 17
- JDK built-in `com.sun.net.httpserver.HttpServer` (no servlet container needed)
- H2 in-memory database
- Maven

## Run

```bash
mvn -q exec:java
```

Then open http://localhost:8080/

## Endpoints

- `GET /` — list of articles + search box
- `GET /article?id=<ID>` — fetches a single article. The `id` value is concatenated
  straight into the SQL string. **Vulnerable: SQL injection.**
- `GET /search?q=<Q>` — searches articles by title. The DB query is parameterised,
  but `q` is written back into the HTML without escaping. **Vulnerable: reflected XSS.**

## Try SQL injection

Normal request:

```
http://localhost:8080/article?id=1
```

UNION-based injection that leaks the `users` table (passwords included):

```
http://localhost:8080/article?id=0 UNION SELECT id, username, password FROM users
```

Boolean trick that returns every article at once:

```
http://localhost:8080/article?id=1 OR 1=1
```

## Try reflected XSS

Normal search:

```
http://localhost:8080/search?q=hello
```

Script-tag payload (pops an alert):

```
http://localhost:8080/search?q=<script>alert('XSS')</script>
```

`onerror` image payload (works even when `<script>` is stripped by a naive filter):

```
http://localhost:8080/search?q=<img src=x onerror=alert('XSS-img')>
```

The query is reflected into the page in two places — the "You searched for" line
and the `value` attribute of the search box — so payloads have multiple sinks
to hit.

## Where the bugs live

`src/main/java/com/example/sqli/Main.java`:

- SQLi — `ArticleHandler.handle`:
  ```java
  ResultSet rs = s.executeQuery(
      "SELECT id, title, body FROM articles WHERE id = " + id);
  ```
- XSS — `SearchHandler.handle`:
  ```java
  "<p>You searched for: <b>" + q + "</b></p>"
  "<input type='text' name='q' value='" + q + "'>"
  ```

## The fixes

**SQLi** — use `PreparedStatement` with bound parameters:

```java
String sql = "SELECT id, title, body FROM articles WHERE id = ?";
try (PreparedStatement ps = c.prepareStatement(sql)) {
    ps.setInt(1, Integer.parseInt(id));
    try (ResultSet rs = ps.executeQuery()) {
        // ...
    }
}
```

The bound parameter is sent separately from the SQL text, so the database never
treats user input as code — only as data.

**XSS** — HTML-escape any user-controlled value before it goes into the page:

```java
"<p>You searched for: <b>" + escape(q) + "</b></p>"
"<input type='text' name='q' value='" + escape(q) + "'>"
```

(The `escape` helper in `Main.java` shows the minimal set of replacements:
`&`, `<`, `>`, `"`, `'`.) In a real codebase, use your template engine's
auto-escaping (Thymeleaf, JSP `c:out`, etc.) rather than hand-rolling it.
