# Install the TypeScript API client

These instructions are for a coding agent working in the user's Node.js project.

1. Inspect the target project and use its existing package manager and lockfile.
   Node.js 18 or newer is required.
2. Ask before changing dependencies or downloading packages.
3. Install `@patronus-protect/api-client` with that package manager. For npm:

   ```sh
   npm install @patronus-protect/api-client
   ```

4. Read the API key only from the existing `PATRONUS_API_KEY` environment
   variable. Never request, print, persist or commit the key.
5. Add the smallest integration required by the user. Follow the examples in
   [`README.md`](README.md); do not perform a live scan unless explicitly asked.
6. Run the project's normal typecheck and tests. At minimum, verify that the
   package imports successfully under the project's ESM configuration.

Report the dependency and lockfile changes and the checks run. If the package
cannot be resolved from the configured registry, stop and report the error; do
not substitute a repository checkout or tarball unless the user requests it.
