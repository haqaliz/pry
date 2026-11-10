const http = require("http");

const port = Number(process.env.PORT) || 3000;
let rateHits = 0;

http
  .createServer((req, res) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
    }

    const cookie = req.headers.cookie || "";
    if (req.url === "/api/items/1" && cookie.includes("session=a")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"id":1,"owner":"a"}');
      return;
    }
    if (req.url === "/api/items/2" && cookie.includes("session=b")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"id":2,"owner":"b"}');
      return;
    }
    if (req.url === "/api/items/2" && cookie.includes("session=a")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"id":2,"owner":"b"}');
      return;
    }
    if (req.url.startsWith("/api/items/")) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end('{"error":"forbidden"}');
      return;
    }

    if (req.url === "/api/users") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"users":[{"id":1,"email":"owner@example.invalid"}]}');
      return;
    }

    if (req.url === "/api/private") {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end('{"error":"unauthorized"}');
      return;
    }

    if (req.url === "/api/rate-limit") {
      rateHits += 1;
      if (rateHits > 3) {
        res.writeHead(429, { "Retry-After": "1", "Content-Type": "text/plain" });
        res.end("slow down\n");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok\n");
      return;
    }

    if (req.url === "/api/no-limit") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok\n");
      return;
    }

    if (req.url.startsWith("/api/fetch")) {
      const target = new URL(req.url, "http://localhost").searchParams.get("url");
      if (!target) {
        res.writeHead(400, { "Content-Type": "text/plain" });
        res.end("missing url\n");
        return;
      }
      fetch(target)
        .then(() => {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("fetched\n");
        })
        .catch(() => {
          res.writeHead(502, { "Content-Type": "text/plain" });
          res.end("fetch failed\n");
        });
      return;
    }

    if (req.url === "/dump.sql") {
      res.writeHead(200, { "Content-Type": "application/sql" });
      res.end(
        "-- pry fixture dump\n" +
          "CREATE TABLE users (id INTEGER, email TEXT);\n" +
          "INSERT INTO users VALUES (1, 'fixture-row@example.invalid');\n"
      );
      return;
    }

    if (req.url === "/.env") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end(
        "DATABASE_URL=postgres://user:pass@db.example/app\n" +
          "SECRET_KEY=supersecretvalue123\n"
      );
      return;
    }

    if (req.url.startsWith("/__pry_missing__")) {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end(
        'Traceback (most recent call last):\n  File "/app/server.js", line 42, in handler\n    boom()\n'
      );
      return;
    }

    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok\n");
  })
  .listen(port, "0.0.0.0");
