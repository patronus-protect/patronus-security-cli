# Contributing

Thank you for helping improve Patronus Security.

## Before opening a change

- Use an issue for substantial behavior or public-contract changes.
- Never commit credentials, private scan inputs, generated reports, model files,
  or content from `~/.patronus-security-scanner`.
- Add focused tests for behavior changes and preserve the documented fail-open
  runtime contract.

## Local checks

Install stable Rust, Node.js 22.19 or newer, Python 3.12, and `cargo-deny`.
Python tests must run through the repository virtual environment.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --locked --all-targets --all-features
cargo deny check licenses
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
npm --prefix sdk/typescript test
.venv/bin/python -m unittest discover -s sdk/python/tests -p 'test_*.py'
```

Native plugin and DeepSeek checks require the pinned DeepSeek Harness checkout;
the release workflow is the authoritative full test matrix.

## Pull requests

Keep changes focused, update public documentation and the changelog when needed,
and describe tests that were run or intentionally skipped.

By contributing, you confirm that you have the right to submit the work and
that it may be distributed under Apache-2.0. Do not submit third-party code,
model assets, logos, fonts, datasets or generated material unless its license
permits redistribution and the required attribution or notice is included.
Clearly identify adapted work and its source in the pull request.
