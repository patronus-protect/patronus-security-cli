"""Small local URL/file checker using the Patronus Python SDK."""

import json
import os
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from patronus_api_client import FileUpload, Patronus, PatronusError

MAX_BYTES = 10 * 1024 * 1024
PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><title>Patronus file checker</title>
<style>body{font:16px system-ui;max-width:640px;margin:4rem auto;padding:0 1rem}form{display:grid;gap:1rem}input,button{font:inherit;padding:.6rem}pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f3f3f3;padding:1rem}</style>
<h1>URL / file checker</h1><form id="scan"><label>Public HTTPS URL <input name="url" type="url" placeholder="https://example.org"></label><p>or</p><label>File <input name="file" type="file"></label><button>Scan</button></form><pre id="result" role="status"></pre>
<script>document.querySelector('#scan').onsubmit=async e=>{e.preventDefault();const output=document.querySelector('#result');output.textContent='Scanning…';const form=new FormData(e.target);const file=form.get('file');const url=form.get('url');if(file&&file.size){form.delete('url')}else if(url){form.delete('file')}else{output.textContent='Choose a URL or file.';return}try{const response=await fetch('/scan',{method:'POST',body:form});const data=await response.json();output.textContent=JSON.stringify(data,null,2)}catch(error){output.textContent=String(error)}};</script></html>"""


class Handler(BaseHTTPRequestHandler):
    client: Patronus

    def send_json(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != "/":
            return self.send_json(404, {"error": "Not found"})
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path != "/scan":
            return self.send_json(404, {"error": "Not found"})
        try:
            local = f"http://127.0.0.1:{self.server.server_port}"
            if self.headers.get("Host") != local.removeprefix("http://") or self.headers.get("Origin", local) != local:
                raise ValueError("Only same-origin local requests are accepted")
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BYTES:
                raise ValueError("Request exceeds 10 MiB")
            if not self.headers.get("Content-Type", "").startswith("multipart/form-data"):
                raise ValueError("Expected form data")
            message = BytesParser(policy=default).parsebytes(
                f'Content-Type: {self.headers["Content-Type"]}\r\nMIME-Version: 1.0\r\n\r\n'.encode()
                + self.rfile.read(length))
            if not message.is_multipart():
                raise ValueError("Invalid form data")
            fields = {part.get_param("name", header="content-disposition"): part
                      for part in message.iter_parts()}
            upload = fields.get("file")
            if upload is not None and upload.get_filename():
                result = self.client.scan_file(FileUpload(
                    upload.get_filename(), upload.get_payload(decode=True),
                    upload.get_content_type()))
            else:
                url_part = fields.get("url")
                url = url_part.get_content().strip() if url_part is not None else ""
                parsed = urlparse(url)
                if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
                    raise ValueError("Enter a public HTTPS URL")
                result = self.client.scan_url(url)
            self.send_json(200, result)
        except (ValueError, PatronusError) as error:
            status = error.status if isinstance(error, PatronusError) else 400
            self.send_json(status or 502, {"error": str(error)})


if __name__ == "__main__":
    key = os.environ.get("PATRONUS_API_KEY")
    if not key:
        raise SystemExit("Set PATRONUS_API_KEY before starting the server")
    Handler.client = Patronus(api_key=key)
    port = int(os.environ.get("PORT", "8002"))
    print(f"http://127.0.0.1:{port}")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
