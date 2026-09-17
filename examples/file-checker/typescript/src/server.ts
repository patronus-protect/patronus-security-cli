import { createServer } from "node:http";
import { Patronus, PatronusError } from "@patronus-protect/api-client";

const key = process.env.PATRONUS_API_KEY;
if (!key) throw new Error("Set PATRONUS_API_KEY before starting the server");
const client = new Patronus({ apiKey: key });
const port = Number(process.env.PORT ?? 8001);
const maxBytes = 10 * 1024 * 1024;

const page = `<!doctype html><html lang="en"><meta charset="utf-8"><title>Patronus file checker</title>
<style>body{font:16px system-ui;max-width:640px;margin:4rem auto;padding:0 1rem}form{display:grid;gap:1rem}input,button{font:inherit;padding:.6rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f3f3;padding:1rem}</style>
<h1>URL / file checker</h1><form id="scan"><label>Public HTTPS URL <input name="url" type="url" placeholder="https://example.org"></label><p>or</p><label>File <input name="file" type="file"></label><button>Scan</button></form><pre id="result" role="status"></pre>
<script>document.querySelector('#scan').onsubmit=async e=>{e.preventDefault();const output=document.querySelector('#result');output.textContent='Scanning…';const form=new FormData(e.target);const file=form.get('file');const url=form.get('url');if(file&&file.size){form.delete('url')}else if(url){form.delete('file')}else{output.textContent='Choose a URL or file.';return}try{const response=await fetch('/scan',{method:'POST',body:form});const data=await response.json();output.textContent=JSON.stringify(data,null,2)}catch(error){output.textContent=String(error)}};</script></html>`;

createServer(async (request, response) => {
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  if (request.method === "GET" && request.url === "/") {
    response.setHeader("Content-Type", "text/html; charset=utf-8");
    response.end(page);
    return;
  }
  if (request.method !== "POST" || request.url !== "/scan") {
    response.writeHead(404).end(JSON.stringify({ error: "Not found" }));
    return;
  }
  try {
    const local = `http://127.0.0.1:${port}`;
    if (request.headers.host !== `127.0.0.1:${port}` ||
        request.headers.origin !== undefined && request.headers.origin !== local)
      throw new Error("Only same-origin local requests are accepted");
    const length = Number(request.headers["content-length"]);
    if (!Number.isSafeInteger(length) || length <= 0 || length > maxBytes) throw new Error("Request exceeds 10 MiB");
    const form = await new Request("http://localhost/scan", {
      method: "POST", headers: { "content-type": request.headers["content-type"] ?? "" },
      body: request as unknown as ReadableStream, duplex: "half"} as RequestInit).formData();
    const file = form.get("file");
    const url = form.get("url");
    const result = file instanceof Blob && file.size
      ? await client.scanFile({ name: "name" in file ? String(file.name) : "upload", data: file, mediaType: file.type || "application/octet-stream" })
      : typeof url === "string" && /^https:\/\/[^\s]+$/.test(url)
        ? await client.scanUrl(url) : null;
    if (!result) throw new Error("Choose a file or public HTTPS URL");
    response.end(JSON.stringify(result));
  } catch (error) {
    response.writeHead(error instanceof PatronusError ? (error.status ?? 502) : 400)
      .end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
  }
}).listen(port, "127.0.0.1", () => console.log(`http://127.0.0.1:${port}`));
