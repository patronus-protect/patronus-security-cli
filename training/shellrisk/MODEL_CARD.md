# Model card: Patronus shell-command risk model (candidate K26)

## What it does

The model takes one shell command as text (POSIX shell, PowerShell or cmd) and returns a risk score.
Combined with Cedar policies over the command's structured facts, it returns one decision:

| Decision | Meaning | Operating point |
|---|---|---|
| `allow` | No risk flag. | |
| `ask` | A human should confirm. | Score above the threshold with 1 % FPR on the validation mixture. |
| `block` | Clearly risky. | Score above the 0.1 % FPR threshold, or a blocking policy fired. |

"Risky" means the command can cause harm that is hard to undo. Examples:

- exfiltrating secrets
- running remote code
- deleting data or system state outside a scratch location
- disabling security controls
- gaining persistence or privileges

Routine developer operations count as safe, for example `git push --force`, `git reset --hard` and
`rm -rf build/`. The model is binary; severity comes from the two thresholds.

**Intended use:** a pre-execution check for commands proposed by coding agents, inside the Patronus runtime.
**Not intended:** malware analysis, scanning scripts longer than a few kilobytes, or any decision without a
human fallback.

## Architecture

- **Blocks.** Two TF-IDF blocks:
  - character n-grams (char_wb, 3–5, 50,000 features)
  - `kf1` tokens, 26,702 features: shell tokens, action markers and `patronus.facts/1` tokens
- **Classifier.** Logistic regression (C = 10) over both blocks.
- **Format.** JSON (`format_version` 2): vocabularies, IDF, weights, thresholds. No pickle, no code.
- **Policies.**
  - 13 core policies
  - translated DefenseClaw rules, each gated to block, ask or rejected by its validation FPR
- **Inference.** Bundle score = max(model score, policy floor). Python p95 is 1.4–1.7× that of the released model
  G. The Rust runtime is the production path.

## Data

| Source | Licence | Use |
|---|---|---|
| tomngdev/shell-safety | MIT | risky and benign commands |
| zyw-286/shell-attack-evolution-dataset | CC-BY-4.0 | honeypot positives |
| redcanaryco/atomic-red-team | MIT | attack commands |
| nebius/SWE-agent-trajectories | CC-BY-4.0 (generated text: Llama-3.1 licence) | benign agent commands |
| ShellRisk-Bench (original) | see source | original bash target |
| infraset/infraset | see dataset card | benign infrastructure-agent commands (fit/val tasks only) |
| DefenseClaw security suite | Apache-2.0 | tool-call commands, relabelled by us. Rules are split by rule id: fit/val rules train, unseen rules evaluate. |
| Patronus synthetic templates | own | benign look-alikes and risky counterparts (fit/val only) |

Evaluation also uses these sources, never for training:

- nl2bash-custom
- rogue-security coding-agent benchmark
- cross-shell robustness sets
- the agent holdout from ai-and/termgrade-trajectories and harithoppil/terminal-bench-2-trajectories (both Apache-2.0)

## Results

All numbers are for the bundle at its own thresholds. Details are in [REPORT.md](REPORT.md).

| | released G | K26 |
|---|---|---|
| Original bash test: AUC / recall at ask | 0.995 / 0.860 | 0.995 / 0.902 |
| Classic corpus test: recall at ask | 0.933 | 0.936 |
| Infraset unseen tasks: FPR at ask | 20.0 % | 2.8 % |
| DefenseClaw unseen rules: AUC / FPR at ask | 0.772 / 44 % | 0.930 / 20 % |
| Real agent commands (15,537): flagged | 0.32 % | 0.24 % |
| Secret-exfiltration probes ≥ Medium | 60/60 | 60/60 |

## Limitations

- **Encoded commands** (base64 pipelines, PowerShell `-EncodedCommand`) are scored at chance level.
- **One command at a time.** Multi-step attacks are caught only by policies over the facts of earlier commands
  (`prior_facts`), when the caller supplies them.
- **Padding.** Long harmless padding before a command (4–16 KB) costs some recall on POSIX commands. The loss is
  smaller than G's, but K26 picks up 4–5 extra false positives per 443 commands.
- **Distribution.** Tuned on agent and developer commands. Administrative scripts on servers have not been
  evaluated separately.
- **Run-to-run differences** of a few rows between candidates are within training noise.
