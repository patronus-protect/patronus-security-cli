# Threat model and scope

Scanned repositories and paths are untrusted. The scanner never executes scanned files, hooks, build scripts, config commands, or repository binaries. It rejects special files and file symlinks, does not follow directory symlinks by default, revalidates metadata before reading, enforces containment and size limits, and hard-excludes `.git` plus the active output root.

Ark supports probabilistic signal classification. This MVP does not establish the absence of SQL injection, SSRF, remote code execution, authorization bugs, insecure cryptography, vulnerable dependencies/CVEs, business-logic flaws, or malicious runtime behavior.
