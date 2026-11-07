const http = require("http");

const port = Number(process.env.PORT) || 3000;

http
  .createServer((req, res) => {
    const origin = req.headers.origin;
    if (origin) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
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
