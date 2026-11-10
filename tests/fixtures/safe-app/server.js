const http = require("http");

const port = Number(process.env.PORT) || 3000;

http
  .createServer((req, res) => {
    res.setHeader("Content-Security-Policy", "default-src 'self'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "geolocation=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    if (req.url.startsWith("/api/fetch")) {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ignored\n");
      return;
    }
    if (req.url === "/api/users" || req.url === "/api/private") {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end('{"error":"unauthorized"}');
      return;
    }
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found\n");
  })
  .listen(port, "0.0.0.0");
