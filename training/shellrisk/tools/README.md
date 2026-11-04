# tools/: provenance scripts

These scripts record how committed or frozen artifacts were produced. They ran in the earlier research
workspace (`benchmark/shellrisk-ensemble-2026-11-03`, not in the repository). They are not part of the
package and do not run from here as they are.

| Script | Produced | Inputs |
|---|---|---|
| `freeze_inputs.py` | the frozen files in `data/manifest.json` | research workspace, Hugging Face cache |
| `translate_dc.py` | DefenseClaw rule packs translated to Cedar conditions | DefenseClaw checkout (Apache-2.0) |
| `translate_dc_facts.py` | `src/shellrisk/policies/dc_rules.json`, the same rules over `patronus.facts/1` | output of `translate_dc.py` |

To regenerate `dc_rules.json`:

1. Point these scripts at a DefenseClaw checkout.
2. Point their imports at `shellrisk.facts.schema`, `shellrisk.policies.cedar` and `shellrisk.segments`.
3. Re-run `shellrisk train`. The policy gate assigns new levels.
