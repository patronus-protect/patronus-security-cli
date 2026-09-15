# Install the Python API client

These instructions are for a coding agent working in the user's Python project.

1. Inspect the target project and reuse its dependency manager and virtual
   environment. If it has none, ask before creating `.venv`. Python 3.10 or
   newer is required.
2. Ask before changing dependencies or downloading packages.
3. Add `patronus-api-client` through the project's dependency manager. For pip:

   ```sh
   python -m pip install patronus-api-client
   ```

4. Read the API key only from the existing `PATRONUS_API_KEY` environment
   variable. Never request, print, persist or commit the key.
5. Add the smallest integration required by the user. Follow the examples in
   [`README.md`](README.md); do not perform a live scan unless explicitly asked.
6. Run the target project's normal tests and verify the import inside its
   virtual environment:

   ```sh
   python -c "from patronus_api_client import Patronus"
   ```

Report the dependency files changed and checks run. If the package cannot be
resolved from the configured index, stop and report the error; do not substitute
a repository checkout or local path unless the user explicitly requests it.
