# `_meta/`

Generated reference material *about* the playbooks in this repo — not playbooks
themselves. Files here are derived artifacts; treat them as read-only and
regenerate rather than hand-edit.

## Contents

| file | what it is | regenerate |
|---|---|---|
| `field_inventory.md` | Catalogue of every field name used in the playbook question queries, grouped by logsource category, with the SO/ECS field each converts to. ECS targets are ground-truth — derived by running `sigma convert` through the deployed pipeline stack. | `python3 scratch/gen_field_inventory.py` |

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
