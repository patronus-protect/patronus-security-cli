#!/usr/bin/env python3
"""Exercise local and hybrid file scans concurrently without retaining payloads."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import tempfile
import time


def bounded_failure_reason(message: object) -> str:
    text = str(message).lower()
    for needle, reason in (
        ("coverage is incomplete", "api_coverage_incomplete"),
        ("usage limit", "usage_limit"),
        ("rate limit", "rate_limit"),
        ("timeout", "timeout"),
        ("authentication", "authentication"),
        ("request failed", "transport"),
    ):
        if needle in text:
            return reason
    return "other"


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def run_scan(binary: Path, config: Path, source: Path, root: Path, index: int) -> dict:
    started = time.monotonic()
    environment = {**os.environ, "PATRONUS_DATA_DIR": str(root / f"data-{index}")}
    result = subprocess.run(
        [
            str(binary),
            "scan",
            "file",
            str(source),
            "--config",
            str(config),
            "--no-repo-config",
            "--output",
            str(root / f"output-{index}"),
            "--format",
            "json",
            "--progress",
            "off",
            "--fail-on",
            "never",
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    elapsed = time.monotonic() - started
    report = None
    if result.stdout.strip():
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            pass
    return {
        "seconds": elapsed,
        "exit_code": result.returncode,
        "status": report.get("status") if isinstance(report, dict) else None,
        "complete": (
            isinstance(report, dict)
            and report.get("status") not in ("INCOMPLETE", "FAILED")
            and report.get("coverage", {}).get("failures") == 0
            and report.get("coverage", {}).get("degraded") is False
        ),
        "failure_kinds": sorted(
            {
                str(failure.get("kind"))
                for failure in report.get("failures", [])
                if isinstance(report, dict) and isinstance(failure, dict)
            }
        )
        if isinstance(report, dict)
        else ["invalid_json_output"],
        "failure_reasons": sorted(
            {
                bounded_failure_reason(failure.get("message"))
                for failure in report.get("failures", [])
                if isinstance(report, dict) and isinstance(failure, dict)
            }
        )
        if isinstance(report, dict)
        else ["invalid_json_output"],
    }


def run_mode(binary: Path, mode: str, requests: int, concurrency: int, tokens: int) -> dict:
    if mode == "hybrid" and not os.environ.get("PATRONUS_API_KEY", "").strip():
        raise SystemExit("PATRONUS_API_KEY is required for the hybrid load test")
    with tempfile.TemporaryDirectory(prefix=f"patronus-{mode}-load-") as temporary:
        root = Path(temporary)
        config = root / "config.toml"
        subprocess.run(
            [str(binary), "config", "init", "--path", str(config), "--provider", mode],
            check=True,
            capture_output=True,
            text=True,
        )
        # Deliberately benign and synthetic. Four whitespace-delimited words approximate one token.
        source = root / "synthetic-load-input.txt"
        sentence = "Quarterly project review confirms normal operations and approved documentation. "
        source.write_text((sentence * max(1, tokens // 9 + 1))[: tokens * 8], encoding="utf-8")
        cpu_before = resource.getrusage(resource.RUSAGE_CHILDREN)
        wall_started = time.monotonic()
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            results = list(
                executor.map(
                    lambda index: run_scan(binary, config, source, root, index),
                    range(requests),
                )
            )
        wall_seconds = time.monotonic() - wall_started
        cpu_after = resource.getrusage(resource.RUSAGE_CHILDREN)
    durations = [item["seconds"] for item in results]
    successful = [item for item in results if item["exit_code"] == 0 and item["complete"] is True]
    return {
        "mode": mode,
        "requests": requests,
        "concurrency": concurrency,
        "synthetic_tokens": tokens,
        "successful": len(successful),
        "failed": requests - len(successful),
        "wall_seconds": round(wall_seconds, 3),
        "throughput_per_second": round(requests / wall_seconds, 3),
        "latency_p50_seconds": round(statistics.median(durations), 3),
        "latency_p95_seconds": round(percentile(durations, 0.95), 3),
        "child_cpu_seconds": round(
            (cpu_after.ru_utime + cpu_after.ru_stime)
            - (cpu_before.ru_utime + cpu_before.ru_stime),
            3,
        ),
        "statuses": sorted({str(item["status"]) for item in results}),
        "failure_kinds": sorted(
            {kind for item in results for kind in item["failure_kinds"]}
        ),
        "failure_reasons": sorted(
            {reason for item in results for reason in item["failure_reasons"]}
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mode", choices=("local", "hybrid", "compare"), default="compare")
    parser.add_argument("--requests", type=int, default=8)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--tokens", type=int, default=4096)
    args = parser.parse_args()
    if args.requests < 1 or args.concurrency < 1 or args.tokens < 2049:
        parser.error("requests/concurrency must be positive and tokens must exceed 2048")
    binary = args.binary.resolve(strict=True)
    modes = ("local", "hybrid") if args.mode == "compare" else (args.mode,)
    reports = [
        run_mode(binary, mode, args.requests, args.concurrency, args.tokens) for mode in modes
    ]
    print(json.dumps({"schema": "patronus.hybrid-load.v1", "results": reports}, indent=2))
    if any(report["failed"] for report in reports):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
