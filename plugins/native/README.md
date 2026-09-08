# Shared native plugin runtime

This directory is the shared source for the Codex and Claude Code runtime adapters. End users should install the host-specific release archive and follow its included README.

The runtime requires Node.js 22.19 or newer and a separately installed, trusted `patronus-security-scanner`. It rejects repository-local scanner executables and unsafe or incompatible runtime configuration. It scans only the external text defined by `docs/runtime-text-contract.md`; static scans are a separate workflow.

For maintainers, build and test from the repository root:

```console
node plugins/native/scripts/build.mjs
node plugins/native/scripts/typecheck.mjs
node plugins/native/scripts/test.mjs
```

The build writes the standalone adapter to `plugins/native/dist/patronus.mjs` and the generated host copies. Edit `plugins/native/src`, not the generated bundles. Runtime dependencies are restricted to Node.js built-ins.

Licensed under Apache-2.0; release packages must include the project `LICENSE` file.
