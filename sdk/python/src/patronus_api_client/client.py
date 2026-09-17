"""Synchronous, dependency-free client for the Patronus Scan API."""

from __future__ import annotations

import json
import mimetypes
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

DEFAULT_BASE_URL = "https://control.patronus.studio/api/v1"
MAX_RESPONSE_BYTES = 1_048_576


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class PatronusError(Exception):
    def __init__(self, message: str, kind: str, *, status: int | None = None,
                 code: str | None = None, request_id: str | None = None,
                 retry_after: int | None = None, details: Any = None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.code = code
        self.request_id = request_id
        self.retry_after = retry_after
        self.details = details


@dataclass(frozen=True)
class FileUpload:
    name: str
    data: bytes
    media_type: str = "application/octet-stream"

    @classmethod
    def from_path(cls, path: str | Path) -> "FileUpload":
        source = Path(path)
        return cls(source.name, source.read_bytes(), mimetypes.guess_type(source.name)[0] or "application/octet-stream")


class Patronus:
    def __init__(self, api_key: str, *, base_url: str = DEFAULT_BASE_URL,
                 timeout: float = 60, poll_interval: float = 0.2):
        parsed = urlparse(base_url)
        local = parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if (parsed.scheme != "https" and not local) or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise PatronusError("API base URL must use HTTPS without credentials, query, or fragment", "validation")
        if not api_key.strip() or "\r" in api_key or "\n" in api_key:
            raise PatronusError("API key is required", "authentication")
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.poll_interval = poll_interval
        self._opener = build_opener(_NoRedirect)

    def submit(self, body: dict[str, Any]) -> dict[str, Any]:
        return self._normalize_submission(self._request("/scan", json.dumps(body).encode(), {"Content-Type": "application/json", "Prefer": "wait=1"}, time.monotonic() + self.timeout))

    def get_job(self, job_id: str) -> dict[str, Any]:
        self._validate_job_id(job_id)
        return self._request(f"/scan/{job_id}", None, {}, time.monotonic() + self.timeout)

    def scan(self, body: dict[str, Any]) -> dict[str, Any]:
        deadline = time.monotonic() + self.timeout
        return self._wait(self._normalize_submission(self._request("/scan", json.dumps(body).encode(), {"Content-Type": "application/json", "Prefer": "wait=1"}, deadline)), deadline)

    def scan_text(self, text: str, *, config: dict[str, Any] | None = None):
        return self.scan({"text": text, **({"config": config} if config is not None else {})})

    def scan_url(self, url: str, *, config: dict[str, Any] | None = None):
        return self.scan({"url": url, **({"config": config} if config is not None else {})})

    def scan_mcp_server(self, url: str, *, config: dict[str, Any] | None = None):
        return self.scan({"mcp_server_url": url, **({"config": config} if config is not None else {})})

    def scan_files(self, files: list[FileUpload | str | Path], *, text: str | None = None,
                   config: dict[str, Any] | None = None):
        if not files:
            raise PatronusError("At least one file is required", "validation")
        uploads = [item if isinstance(item, FileUpload) else FileUpload.from_path(item) for item in files]
        boundary = f"patronus-{uuid.uuid4().hex}"
        body = bytearray()
        for upload in uploads:
            if not upload.name or any(value in upload.name for value in ('\r', '\n', '"')) or any(value in upload.media_type for value in ('\r', '\n')):
                raise PatronusError("Invalid file metadata", "validation")
            body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="files"; filename="{upload.name}"\r\nContent-Type: {upload.media_type}\r\n\r\n'.encode())
            body.extend(upload.data)
            body.extend(b"\r\n")
        fields = {"text": text, "config": json.dumps(config) if config is not None else None}
        for name, value in fields.items():
            if value is not None:
                body.extend(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
        body.extend(f"--{boundary}--\r\n".encode())
        deadline = time.monotonic() + self.timeout
        response = self._normalize_submission(self._request("/scan", bytes(body), {"Content-Type": f"multipart/form-data; boundary={boundary}", "Prefer": "wait=1"}, deadline))
        return self._wait(response, deadline)

    def scan_file(self, file: FileUpload | str | Path, *, text: str | None = None,
                  config: dict[str, Any] | None = None):
        return self.scan_files([file], text=text, config=config)

    @classmethod
    def _normalize_submission(cls, value: dict[str, Any]) -> dict[str, Any]:
        if isinstance(value.get("jobs"), list):
            return value
        if value.get("status") not in {"completed", "failed"} or cls._invalid_job_id(value.get("job_id")):
            return value

        job = dict(value)
        response = {"status": "completed", "jobs": [job]}
        for field in ("input", "extraction", "coverage", "usage", "request_id"):
            job.pop(field, None)
            if field in value:
                response[field] = value[field]
        return response

    def _wait(self, submission: dict[str, Any], deadline: float):
        if submission.get("status") == "completed":
            jobs = submission.get("jobs")
            if not isinstance(jobs, list) or not 0 < len(jobs) <= 32 or any(not isinstance(job, dict) or job.get("status") not in {"completed", "failed"} or self._invalid_job_id(job.get("job_id")) for job in jobs):
                raise PatronusError("Invalid completed API response", "protocol")
            return submission
        accepted = submission.get("jobs")
        if submission.get("status") != "accepted" or not isinstance(accepted, list) or not 0 < len(accepted) <= 32:
            raise PatronusError("Invalid API jobs", "protocol")
        jobs = []
        for item in accepted:
            job_id = item.get("job_id") if isinstance(item, dict) else None
            self._validate_job_id(job_id)
            while True:
                job = self._request(f"/scan/{job_id}", None, {}, deadline)
                status = job.get("status")
                if status in {"queued", "running"}:
                    time.sleep(min(self.poll_interval, self._remaining(deadline)))
                elif isinstance(status, str):
                    jobs.append(job)
                    break
                else:
                    raise PatronusError("Missing API job status", "protocol")
        return {**submission, "status": "completed" if all(job["status"] == "completed" for job in jobs) else "failed", "jobs": jobs}

    @staticmethod
    def _validate_job_id(job_id: Any):
        if Patronus._invalid_job_id(job_id):
            raise PatronusError("Invalid API job identifier", "protocol")

    @staticmethod
    def _invalid_job_id(job_id: Any):
        return not isinstance(job_id, str) or len(job_id) != 36 or not job_id.startswith("job_") or any(value not in "0123456789abcdefABCDEF" for value in job_id[4:])

    @staticmethod
    def _remaining(deadline: float):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PatronusError("API scan timeout", "timeout")
        return remaining

    def _request(self, path: str, body: bytes | None, headers: dict[str, str], deadline: float):
        request = Request(f"{self.base_url}{path}", data=body, headers={"Accept": "application/json", "Authorization": f"Bearer {self.api_key}", "User-Agent": "patronus-api-client-python/0.1.1", **headers}, method="POST" if body is not None else "GET")
        try:
            with self._opener.open(request, timeout=self._remaining(deadline)) as response:
                return self._decode(response)
        except HTTPError as error:
            value = self._decode(error, allow_invalid=True)
            details = value.get("error", value) if isinstance(value, dict) else {}
            code = details.get("code") if isinstance(details.get("code"), str) else None
            kind = "authentication" if error.code in {401, 403} else "quota" if error.code == 429 and code and "QUOTA" in code else "rate_limit" if error.code == 429 else "validation" if error.code in {400, 404, 409, 413, 422} else "transport"
            retry = error.headers.get("retry-after")
            raise PatronusError(details.get("message", "API request failed"), kind, status=error.code, code=code, request_id=details.get("request_id") or error.headers.get("x-request-id"), retry_after=int(retry) if retry and retry.isdigit() else None, details=value) from None
        except (URLError, TimeoutError) as error:
            kind = "timeout" if isinstance(error, TimeoutError) or "timed out" in str(error).lower() else "transport"
            raise PatronusError("API scan timeout" if kind == "timeout" else "API request failed", kind) from None

    @staticmethod
    def _decode(response, *, allow_invalid=False):
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise PatronusError("API response exceeds limit", "protocol")
        try:
            value = json.loads(data)
            if not isinstance(value, dict):
                raise ValueError
            return value
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            if allow_invalid:
                return {}
            raise PatronusError("Invalid API response", "protocol") from None
