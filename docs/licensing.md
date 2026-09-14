# Licensing

The Patronus Security CLI and the first-party integrations in this
repository are distributed under the Apache License 2.0. The complete terms are
in the repository's `LICENSE` file and accompany release artifacts.

This distribution uses exactly `patronus-ark 0.1.7`, pinned in `Cargo.toml` and
`Cargo.lock`. The copy currently published through crates.io declares
`GPL-3.0-only` in its package metadata and includes its own `LICENSE`,
`LICENSE-COMMERCIAL.md`, and `NOTICE` files. Casdo Labs GmbH / Patronus owns ARK
and has authorized its inclusion in this Apache-2.0 distribution under different
terms. This authorization applies to this distribution; it does not alter or
relabel the metadata of the separately published crates.io artifact.

This boundary is checked by `cargo deny check licenses`. The repository's
`deny.toml` accepts `GPL-3.0-only` only for the exact `patronus-ark` package;
it does not allow GPL dependencies generally. The CLI package itself
continues to declare `Apache-2.0` in `Cargo.toml`.

Third-party components remain under their respective licenses. In particular,
the embedded Manrope and Inter font subsets retain their SIL Open Font License
notices in `src/dashboard/assets/Manrope-OFL.txt` and `src/dashboard/assets/Inter-OFL.txt`.
