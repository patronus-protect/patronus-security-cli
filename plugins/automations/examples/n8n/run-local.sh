#!/usr/bin/env bash
# Local n8n example environment without Docker.
#   setup  build and install the Patronus community node, import credentials and the two example workflows
#   start  start n8n on http://localhost:5678 (foreground)
#   stub   start the recording LLM stub on http://127.0.0.1:4100 (foreground)
# Requires Node >= 24 (n8n 2.x), Ollama with nomic-embed-text for the RAG example,
# and PATRONUS_API_KEY in the environment or in the repository's .env file.
set -euo pipefail

N8N_VERSION=2.42.4
here="$(cd "$(dirname "$0")" && pwd)"
automations="$(cd "$here/../.." && pwd)"
repo="$(cd "$automations/../.." && pwd)"
runtime="${N8N_RUNTIME_DIR:-$repo/tmp/n8n-runtime}"
export N8N_USER_FOLDER="${N8N_USER_FOLDER:-$repo/tmp/n8n-home}"
export N8N_DIAGNOSTICS_ENABLED=false N8N_PERSONALIZATION_ENABLED=false N8N_VERSION_NOTIFICATIONS_ENABLED=false
# The default "vm" expression engine needs the native isolated-vm build skipped below.
export N8N_EXPRESSION_ENGINE="${N8N_EXPRESSION_ENGINE:-legacy}"
export N8N_HOST=localhost N8N_PORT="${N8N_PORT:-5678}" N8N_PROTOCOL=http WEBHOOK_URL="http://localhost:${N8N_PORT:-5678}/"

node_major="$(node -p 'process.versions.node.split(".")[0]')"
if (( node_major < 24 )); then
  echo "n8n $N8N_VERSION needs Node >= 24 (found $(node -v)). Put a newer node first in PATH." >&2
  exit 1
fi

n8n() { "$runtime/node_modules/.bin/n8n" "$@"; }

install_runtime() {
  if [[ "$(n8n --version 2>/dev/null || true)" != "$N8N_VERSION" ]]; then
    mkdir -p "$runtime"
    # isolated-vm does not compile on Node 25; the examples do not need its native build.
    (cd "$runtime" && { [[ -f package.json ]] || npm init -y >/dev/null; } && npm install --no-audit --no-fund --ignore-scripts "n8n@$N8N_VERSION" && npm rebuild sqlite3)
  fi
}

install_node_package() {
  # Same artifact and loading route as a published community node: npm package in ~/.n8n/nodes.
  (cd "$automations" && npm run build >/dev/null)
  local nodes="$N8N_USER_FOLDER/.n8n/nodes"
  mkdir -p "$nodes"
  local tarball
  tarball="$(cd "$automations/n8n" && npm pack --silent --pack-destination "$nodes")"
  # n8n provides n8n-workflow itself, so the package's peer dependency is not installed.
  (cd "$nodes" && { [[ -f package.json ]] || npm init -y >/dev/null; } && npm install --no-audit --no-fund --omit=peer --ignore-scripts "./$tarball" >/dev/null)
  echo "installed $tarball into $nodes"
}

import_credentials() {
  local key="${PATRONUS_API_KEY:-}"
  if [[ -z "$key" && -f "$repo/.env" ]]; then
    key="$(set -a; . "$repo/.env"; printf '%s' "${PATRONUS_API_KEY:-}")"
  fi
  [[ -n "$key" ]] || { echo "PATRONUS_API_KEY is not set (environment or $repo/.env)." >&2; exit 1; }
  local file
  file="$(mktemp "${TMPDIR:-/tmp}/patronus-n8n-credentials.XXXXXX")"
  trap 'rm -f "$file"' RETURN
  PATRONUS_API_KEY="$key" node -e '
    const fs = require("node:fs");
    fs.writeFileSync(process.argv[1], JSON.stringify([
      { id: "patronusLocalApi", name: "Patronus API", type: "patronusApi", data: { apiKey: process.env.PATRONUS_API_KEY } },
      { id: "ollamaLocal", name: "Ollama (local)", type: "ollamaApi", data: { baseUrl: process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434" } },
    ]), { mode: 0o600 });' "$file"
  n8n import:credentials --input="$file" >/dev/null
  echo "imported credentials: Patronus API, Ollama (local)"
}

import_workflows() {
  node "$here/build-workflows.mjs" >/dev/null
  for workflow in chatbot rag; do
    n8n import:workflow --input="$here/$workflow.workflow.json" >/dev/null
  done
  n8n publish:workflow --id=patronusChatbot1 >/dev/null
  n8n publish:workflow --id=patronusRagFlow1 >/dev/null
  echo "imported and published workflows: patronusChatbot1, patronusRagFlow1"
}

case "${1:-}" in
  setup) install_runtime; install_node_package; import_credentials; import_workflows ;;
  start) exec "$runtime/node_modules/.bin/n8n" start ;;
  stub) LLM_STUB_LOG="${LLM_STUB_LOG:-$repo/tmp/llm-stub/llm-calls.jsonl}" exec node "$automations/examples/llm-stub/server.mjs" ;;
  *) echo "usage: $0 setup|start|stub" >&2; exit 2 ;;
esac
