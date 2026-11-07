const http = require("http");

const port = Number(process.env.PORT) || 3000;

http
  .createServer((req, res) => {
    res.writeHead(404, { "Content-Type": "text/plain" });
    res.end("Not found\n");
  })
  .listen(port, "0.0.0.0");
