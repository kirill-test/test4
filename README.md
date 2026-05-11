# SQL Injection Demo (Java)

A minimal Java web app to demonstrate the risk of SQL injection.
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

- `GET /` — list of articles
- `GET /article?id=<ID>` — fetches a single article. The `id` value is concatenated
  straight into the SQL string. This is the vulnerable code path.

## Try the injection

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

The "Executed SQL" panel on the article page shows the exact query that was sent,
making it easy to walk developers through what happened.

## Where the bug lives

`src/main/java/com/example/sqli/Main.java`, inside `ArticleHandler.handle`:

```java
String sql = "SELECT id, title, body FROM articles WHERE id = " + id;
```

## The fix

Use `PreparedStatement` with bound parameters:

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
