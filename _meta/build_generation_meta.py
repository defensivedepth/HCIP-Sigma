#!/usr/bin/env python3
"""Generate _meta/generation_meta.json — the provenance index for the playbooks.

Every playbook in ../sigma/*.yaml carries two kinds of build-time provenance that
are noise to an analyst running the playbook in Security Onion but valuable when
auditing how the corpus was generated:

  * `_generation_meta` — techniques, attack-chain / dimension coverage, dedup and
    hint dispositions, the template sets applied, and generation stats.
  * a per-question `source:` marker (e.g. `template:cue_process_tool.scope`,
    `attack:T1548.002.registry_set`) recording which template or ATT&CK analytic
    produced each question.

This script lifts both out of every playbook into a single JSON document and a
corpus-level rollup, so the provenance can be browsed (see generation_meta.html)
without bloating the playbooks themselves. It does NOT modify the playbooks.

    python3 _meta/build_generation_meta.py
"""
import json
import os
import pathlib
from collections import Counter

META = pathlib.Path(__file__).resolve().parent
# IMPORTANT: this archive can only be built from playbooks that still carry their
# `_generation_meta` block and per-question `source:` markers. Those are stripped
# from the published playbooks, so once stripping has happened, point SIGMA_DIR at
# a pre-strip tree (e.g. a `git archive HEAD sigma` extract, or the generation
# pipeline's pre-publish output). Running against the stripped tree yields an
# empty archive.
SIGMA = pathlib.Path(os.environ.get("SIGMA_DIR") or (META.parent / "sigma"))
OUT = META / "generation_meta.json"

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")


def first_line(text):
    if not text:
        return ""
    return " ".join(str(text).split())


def source_kind(src):
    """`template:foo.bar` -> 'template', `attack:T1.image_load` -> 'attack'."""
    if not src or ":" not in src:
        return "unknown"
    return src.split(":", 1)[0]


def template_family(src):
    """`template:cue_process_tool.scope` -> 'cue_process_tool'. None for non-templates."""
    if not src or not src.startswith("template:"):
        return None
    body = src.split(":", 1)[1]
    return body.split(".", 1)[0] if "." in body else body


def main():
    entries = []
    # Corpus-level tallies
    source_count = Counter()       # full source string -> uses
    kind_count = Counter()         # template / attack / unknown -> uses
    family_count = Counter()       # template family -> uses
    set_count = Counter()          # technique_sets_applied -> playbooks
    technique_count = Counter()    # ATT&CK id -> playbooks
    playbooks_missing_meta = []

    for path in sorted(SIGMA.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"  skip {path.name}: {e}")
            continue

        meta = data.get("_generation_meta") or {}
        if not meta:
            playbooks_missing_meta.append(path.stem)

        questions = []
        for i, q in enumerate(data.get("questions") or [], start=1):
            src = q.get("source")
            # `kind` is intentionally not stored — it's derivable from the source
            # prefix (`template:` / `attack:`); the viewer computes it on the fly.
            questions.append({
                "n": i,
                "source": src,
                "question": first_line(q.get("question")),
            })
            if src:
                source_count[src] += 1
                kind_count[source_kind(src)] += 1
                fam = template_family(src)
                if fam:
                    family_count[fam] += 1

        for s in meta.get("technique_sets_applied") or []:
            set_count[s] += 1
        for t in meta.get("techniques") or []:
            if t.get("id"):
                technique_count[t["id"]] += 1

        entries.append({
            "id": path.stem,
            "name": data.get("name", path.stem),
            "description": first_line(data.get("description"))[:300],
            "question_count": len(questions),
            "questions": questions,
            "generation_meta": meta,
        })

    entries.sort(key=lambda e: e["name"].lower())

    rollup = {
        "playbooks": len(entries),
        "playbooks_missing_meta": playbooks_missing_meta,
        "total_questions": sum(e["question_count"] for e in entries),
        "source_kinds": dict(kind_count.most_common()),
        "template_families": dict(family_count.most_common()),
        "technique_sets_applied": dict(set_count.most_common()),
        "techniques": dict(technique_count.most_common()),
        "sources": dict(source_count.most_common()),
    }

    doc = {"rollup": rollup, "playbooks": entries}
    # Compact separators: this is a generated, machine-read artifact (the HTML
    # viewer parses it) — the data is ~10 MB of unique prose, so pretty-printing
    # only adds whitespace. Use `jq` if you need to read it by hand.
    OUT.write_text(json.dumps(doc, separators=(",", ":")) + "\n")

    print(f"Wrote {len(entries)} playbooks -> {OUT.relative_to(META.parent)}")
    print(f"  {rollup['total_questions']} questions, "
          f"{len(family_count)} template families, "
          f"{len(set_count)} technique sets")
    if playbooks_missing_meta:
        print(f"  WARNING: {len(playbooks_missing_meta)} playbooks have no _generation_meta")


if __name__ == "__main__":
    main()
