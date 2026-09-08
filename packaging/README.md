# Plugin packaging

End users install a target-specific CLI ZIP and do not build Rust. Codex and Claude plugins are platform-independent and contain no executable. Maintainers create the CLI archive and, once per release, the plugin archives after a release build:

```console
cargo run --bin package-plugins -- target/release/patronus-security-scanner <rust-target> dist --include-plugins
```

The CLI archive contains only the supplied executable, `INSTALL.md`, the project
license, the third-party notice, and the two bundled font-license notices. With
`--include-plugins`, the packager creates platform-independent Codex and Claude
ZIPs from fixed runtime-file allowlists; they contain no scanner binary or test
artifacts. Release CI publishes SHA-256 and BLAKE3 checksums for every archive.

Release CI also publishes `install.sh` and its verified Python backend
`install.py`, with individual SHA-256 and BLAKE3 checksums. `install.sh` is the
public entry point and starts CLI onboarding by default.

The Codex `submission/` dossier is maintainer material and is excluded from the installable plugin archive.
