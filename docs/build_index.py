#!/usr/bin/env python3
"""Generate docs/playbooks.json — a lightweight search index for the lookup page.

Scans ../sigma/*.yaml and emits {id, name, description, questions} per playbook.
The index powers search-by-name; preview content is fetched live from GitHub so
it always reflects the current repo. Re-run after adding or editing playbooks:

    python3 docs/build_index.py
"""
import json
import pathlib

DOCS = pathlib.Path(__file__).resolve().parent
SIGMA = DOCS.parent / "sigma"
OUT = DOCS / "playbooks.json"

try:
    import yaml
except ImportError:
    raise SystemExit("PyYAML required: pip install pyyaml")


def first_line(text):
    if not text:
        return ""
    return " ".join(str(text).split())


def techniques_of(data):
    meta = data.get("_generation_meta") or {}
    out = []
    for t in meta.get("techniques") or []:
        tid = t.get("id")
        if tid:
            out.append({"id": tid, "name": t.get("name", "")})
    return out


def data_sources_of(data):
    """Distinct logsource categories used across the playbook's question queries."""
    meta = data.get("_generation_meta") or {}
    diversity = (meta.get("generation_stats") or {}).get("logsource_diversity") or {}
    if diversity:
        return sorted(diversity.keys())
    # Fallback: parse each question query's logsource.category
    cats = set()
    for q in data.get("questions") or []:
        try:
            qq = yaml.safe_load(q.get("query", "") or "")
        except yaml.YAMLError:
            continue
        if isinstance(qq, dict):
            cat = (qq.get("logsource") or {}).get("category")
            if cat:
                cats.add(cat)
    return sorted(cats)


def main():
    entries = []
    for path in sorted(SIGMA.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text()) or {}
        except yaml.YAMLError as e:
            print(f"  skip {path.name}: {e}")
            continue
        entries.append({
            "id": path.stem,
            "name": data.get("name", path.stem),
            "description": first_line(data.get("description"))[:400],
            "questions": len(data.get("questions") or []),
            "techniques": techniques_of(data),
            "data_sources": data_sources_of(data),
        })

    entries.sort(key=lambda e: e["name"].lower())
    OUT.write_text(json.dumps(entries, indent=2) + "\n")

    techs = {t["id"] for e in entries for t in e["techniques"]}
    srcs = {s for e in entries for s in e["data_sources"]}
    print(f"Wrote {len(entries)} playbooks -> {OUT.relative_to(DOCS.parent)}")
    print(f"  {len(techs)} ATT&CK techniques, {len(srcs)} data sources")


if __name__ == "__main__":
    main()
