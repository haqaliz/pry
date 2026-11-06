const http = require("http");

const port = Number(process.env.PORT) || 3000;

http
  .createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("pry node fixture\n");
  })
  .listen(port, "127.0.0.1");
