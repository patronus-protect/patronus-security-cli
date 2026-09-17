"""Exercise both local webapps against the live Patronus API."""

import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
EXAMPLE = ROOT / "examples/file-checker"


def api_key():
    # Read only the requested variable. Never print the key or the .env contents.
    for line in (ROOT / ".env").read_text().splitlines():
        name, separator, value = line.partition("=")
        if separator and name.strip().removeprefix("export ").strip() == "PATRONUS_API_KEY":
            return value.strip().strip("\"'")
    raise RuntimeError("PATRONUS_API_KEY is missing from .env")


def form_body(field, value, filename=None):
    boundary = "patronus-e2e-" + uuid.uuid4().hex
    disposition = f'form-data; name="{field}"'
    if filename:
        disposition += f'; filename="{filename}"'
    content_type = "text/plain" if filename else "text/plain; charset=utf-8"
    body = (f"--{boundary}\r\nContent-Disposition: {disposition}\r\n"
            f"Content-Type: {content_type}\r\n\r\n").encode() + value + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def check(base_url, field, value, filename=None):
    body, content_type = form_body(field, value, filename)
    request = Request(base_url + "/scan", body, {"Content-Type": content_type})
    try:
        with urlopen(request, timeout=100) as response:
            result = json.load(response)
            status = response.status
    except HTTPError as error:
        status = error.code
        result = json.load(error)
    if status != 200 or result.get("status") != "completed" or not result.get("jobs"):
        raise AssertionError(f"HTTP {status}: scan did not complete")
    print(f"  {field}: HTTP {status}, {len(result['jobs'])} completed job(s)")


def run(name, command, port, environment):
    base_url = f"http://127.0.0.1:{port}"
    process = subprocess.Popen(command, cwd=ROOT, env={**environment, "PORT": str(port)},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            if process.poll() is not None:
                raise RuntimeError(f"{name} server exited before startup")
            try:
                with urlopen(base_url, timeout=1) as response:
                    if response.status == 200:
                        break
            except URLError:
                time.sleep(0.1)
        else:
            raise RuntimeError(f"{name} server did not start")
        print(name)
        check(base_url, "file", b"Hello from the Patronus SDK E2E test.\n", "sample.txt")
        check(base_url, "url", b"https://example.org/")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


if __name__ == "__main__":
    environment = {**os.environ, "PATRONUS_API_KEY": api_key()}
    environment["PYTHONPATH"] = str(ROOT / "sdk/python/src") + os.pathsep + environment.get("PYTHONPATH", "")
    run("TypeScript", ["node", str(EXAMPLE / "typescript/dist/server.js")], 18001, environment)
    run("Python", [str(ROOT / ".venv/bin/python"), str(EXAMPLE / "python/app.py")], 18002, environment)
