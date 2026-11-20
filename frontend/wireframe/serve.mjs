// The local design preview serves only the built document, on loopback.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const document = new URL("../../docs/wireframe.html", import.meta.url);
createServer(async (request, response) => {
  const path = new URL(request.url, "http://127.0.0.1").pathname;
  if (!["/", "/wireframe.html"].includes(path) || !["GET", "HEAD"].includes(request.method)) {
    response.writeHead(404).end();
    return;
  }
  try {
    const bytes = await readFile(document);
    response.writeHead(200, {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    });
    response.end(request.method === "HEAD" ? undefined : bytes);
  } catch {
    response.writeHead(503).end();
  }
}).listen(8786, "127.0.0.1");
