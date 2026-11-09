const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const lookup = require("./api/lookup");

const index = fs.readFileSync(path.join(__dirname, "index.html"));
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  if (url.pathname === "/healthz" && req.method === "GET") {
    res.writeHead(200, { "Content-Type": "application/json", "Cache-Control": "no-store" });
    return res.end(JSON.stringify({ status: "ok" }));
  }
  if ((url.pathname === "/" || url.pathname === "/index.html") && ["GET", "HEAD"].includes(req.method)) {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
    return res.end(req.method === "HEAD" ? undefined : index);
  }
  if (url.pathname !== "/api/lookup") {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Not found." }));
  }

  req.query = Object.fromEntries(url.searchParams.entries());
  if (req.method === "POST") {
    let body = "";
    try {
      for await (const chunk of req) {
        body += chunk;
        if (Buffer.byteLength(body) > 8192) {
          res.writeHead(413, { "Content-Type": "application/json" });
          return res.end(JSON.stringify({ error: "Request body is too large." }));
        }
      }
      req.body = body ? JSON.parse(body) : {};
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      return res.end(JSON.stringify({ error: "Request body must be valid JSON." }));
    }
  }
  return lookup(req, res);
});

const port = Number(process.env.PORT || 10000);
server.listen(port, "0.0.0.0", () => {
  console.log("Signal listening on port " + port);
});

