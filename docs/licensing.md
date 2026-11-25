# Licensing

The Patronus Security CLI and the first-party integrations in this
repository are distributed under the Apache License 2.0. The complete terms are
in the repository's `LICENSE` file and accompany release artifacts.

This distribution uses exactly `patronus-ark-core 0.1.18` (Ark Core), pinned in
`Cargo.toml` and `Cargo.lock` and licensed `MIT OR Apache-2.0`. The full
`patronus-ark` gateway (`GPL-3.0-only`) is not a dependency. `cargo deny check
licenses` keeps that boundary: `deny.toml` allows no GPL dependency.

Third-party components remain under their respective licenses. In particular,
the embedded Manrope and Inter font subsets retain their SIL Open Font License
notices in `src/dashboard/assets/Manrope-OFL.txt` and `src/dashboard/assets/Inter-OFL.txt`.
