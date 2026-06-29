# `_meta/`

Generated reference material *about* the playbooks in this repo — not playbooks
themselves. Files here are derived artifacts; treat them as read-only and
regenerate rather than hand-edit.

## Contents

| file | what it is | regenerate |
|---|---|---|
| `field_inventory.md` | Catalogue of every field name used in the playbook question queries, grouped by logsource category, with the SO/ECS field each converts to. ECS targets are ground-truth — derived by running `sigma convert` through the deployed pipeline stack. | `python3 scratch/gen_field_inventory.py` |
| `generation_meta.json` | Build-time provenance lifted out of every playbook: the per-question `source:` marker (which template / ATT&CK analytic produced each question) and the full `_generation_meta` audit block (techniques, attack-chain & dimension coverage, dedup and hint dispositions, template sets applied, generation stats), plus a corpus-level rollup. | `python3 _meta/build_generation_meta.py` |
| `../docs/generation_meta.html` | Self-contained viewer for `generation_meta.json`. **Lives in `docs/`, not here** — GitHub Pages publishes only `docs/` and Jekyll ignores `_`-prefixed dirs, so a viewer under `_meta/` would not be web-served. It fetches this archive from `raw.githubusercontent.com`. Live at `https://defensivedepth.github.io/HCIP-Sigma/generation_meta.html` (linked from the site index). | n/a (static) |

> **Regenerating `generation_meta.json`:** the published playbooks no longer carry
> the `_generation_meta` block or per-question `source:` markers (they were stripped
> into this archive). Running the generator against the stripped `sigma/` tree
> produces an **empty** archive. Point it at a pre-strip tree instead:
> ```bash
> TMP=$(mktemp -d) && git archive HEAD sigma | tar -x -C "$TMP"
> SIGMA_DIR="$TMP/sigma" python3 _meta/build_generation_meta.py && rm -rf "$TMP"
> ```
> Better, regenerate it at generation time from the pipeline's pre-publish output.
> `generation_meta.json` uses compact (no-whitespace) JSON — read it with `jq`.

## Field-name convention (summary)

Playbook queries use **Sigma-spec field names** (`Image`, `CommandLine`,
`ImageLoaded`, `EventID`, `Channel`, `ParentName`, …). The SO pipeline
(`sigma_so_pipeline.yaml` + `ecs_windows`) maps them to ECS at convert time.

The only bare ECS field names allowed are the **platform floor** — host scoping
and prior-detection lookup, which have no Sigma-taxonomy expression:
`host.name`, `rule.uuid`, `rule.name`, `event.module`, `event.severity_label`.

This is enforced at authoring time by `lint_ecs_field_names` in
`5_validate/normalize_and_validate.py` and documented in
`4_playbook/AGENTS.md` ("Field names: use Sigma-spec, never raw ECS").
See `field_inventory.md` for the full field→ECS mapping.
