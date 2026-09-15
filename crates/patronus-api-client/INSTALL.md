# Install the Rust API client

These instructions are for a coding agent working in the user's Rust project.

1. Inspect the target project and confirm it uses Cargo.
2. Ask before changing dependencies or downloading packages.
3. Add the published client:

   ```sh
   cargo add patronus-api-client
   ```

4. Read the API key only from the existing `PATRONUS_API_KEY` environment
   variable. Never request, print, persist or commit the key.
5. Add the smallest integration required by the user. Follow the examples in
   [`README.md`](README.md); do not perform a live scan unless explicitly asked.
6. Run the target project's normal formatting, build and test commands. At
   minimum, verify the dependency with:

   ```sh
   cargo check
   ```

Report the files changed and checks run. If the package cannot be resolved from
crates.io, stop and report the registry error; do not substitute a Git or local
path dependency unless the user explicitly requests it.
