const http = require("http");

const port = Number(process.env.PORT) || 3000;

// The run phase uses --network=none. A real egress attempt must fail.
http
  .createServer((req, res) => {
    fetch("http://203.0.113.1/").then(
      () => console.log("EGRESS_OK"),
      () => console.log("EGRESS_FAILED")
    ).finally(() => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok\n");
    });
  })
  .listen(port, "127.0.0.1");
