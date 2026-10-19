#!/usr/bin/env python3
"""Regenerate references/cwe-index.md from reports.sqlite.

The CWE column stores human-readable labels (not CWE numbers), and the same
bug class is spelled several ways. This groups every label present in the
database into a family so an agent can filter with one IN (...) list.

Usage:
    python3 scripts/gen_cwe_index.py [db-path] [-o out-path]
"""

import argparse
import os
import re
import sqlite3
from collections import OrderedDict

# First matching family wins, so order matters: the more specific pattern must
# come before the broader one (CSRF before SSRF, AI before disclosure).
FAMILIES = OrderedDict([
    ("AI / LLM", r"llm\d|prompt injection|misinformation"),
    ("IDOR / BOLA", r"insecure direct object|\bidor\b|\bbola\b|object level"),
    ("XSS", r"scripting|\bxss\b"),
    ("CSRF", r"cross-site request forgery|\bcsrf\b"),
    ("SSRF", r"server-side request forgery|server side request forgery"),
    ("SQL injection", r"sql injection|blind sql|\bsqli\b"),
    ("XXE", r"external entit|\bxxe\b"),
    ("HTTP smuggling / splitting", r"request smuggling|response splitting"),
    ("Clickjacking", r"clickjacking|ui redressing"),
    ("Access control", r"access control|authorization|privilege|permission|missing function level"),
    ("Authentication / session", r"^(?!.*hard-?coded).*(authentication|credential|password|session|logout|token|brute force)"),
    ("Information disclosure", r"information|disclosure|exposure|cleartext"),
    ("Path traversal / file inclusion", r"path traversal|traversal|file inclusion|file name"),
    ("Injection / code execution", r"injection|neutralization|deserializ|serializ|expression language|template|formula elements|command"),
    ("Business logic", r"business logic|logic error"),
    ("Resource exhaustion / DoS", r"resource consumption|denial of service|excessive|allocation|amplification|uncontrolled"),
    ("Cryptography / randomness", r"cryptograph|encrypt|certificate|random|hard-coded cryptographic|man-in-the-middle"),
    ("Configuration / design", r"misconfiguration|secure design|configuration|default|hard-coded|hardcoded|violation of secure"),
    ("Input validation / encoding", r"validation|encoding|data type|whitespace|delimiter|case sensitivity|unexpected|syntactic"),
    ("Open redirect", r"redirect"),
    ("Race condition / concurrency", r"race|concurren|time-of-check|toctou"),
    ("Memory safety", r"memory|buffer|stack|heap|integer|pointer|use after|out-of-bounds|null|double free|type confusion|off-by-one|underflow|overflow|wrap-around|write-what-where|format string"),
    ("File upload / extensions", r"upload|file extension|unrestricted file"),
    ("Logging / privacy", r"logging|log file|privacy"),
])


def family_for(label):
    low = label.lower()
    for name, pattern in FAMILIES.items():
        if re.search(pattern, low):
            return name
    return "Other"


def sql_list(labels):
    return "(" + ", ".join("'" + l.replace("'", "''") + "'" for l in labels) + ")"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("db", nargs="?", default="reports.sqlite")
    ap.add_argument("-o", "--out", default="references/cwe-index.md")
    args = ap.parse_args()

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    rows = db.execute(
        "SELECT cwe, COUNT(*) FROM reports WHERE cwe != '' GROUP BY cwe"
    ).fetchall()

    total = sum(n for _, n in rows)
    unclassified = db.execute("SELECT COUNT(*) FROM reports WHERE cwe = ''").fetchone()[0]
    all_reports = db.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    groups = OrderedDict()
    for label, n in rows:
        groups.setdefault(family_for(label), []).append((label, n))
    for items in groups.values():
        items.sort(key=lambda x: (-x[1], x[0]))
    ordered = sorted(groups.items(), key=lambda kv: -sum(n for _, n in kv[1]))

    out = []
    out.append("# CWE index\n")
    out.append(
        "Every distinct `cwe` label in `reports.sqlite`, deduplicated and grouped by bug class. "
        "The column stores human-readable names, not CWE numbers.\n"
    )
    out.append(
        f"Snapshot: **{len(rows)} distinct labels**, {total} classified reports, "
        f"{unclassified} unclassified, {all_reports} total. "
        f"Report IDs 1-{db.execute('SELECT MAX(report_id) FROM reports').fetchone()[0]}.\n"
    )
    out.append(
        "Regenerate after scraping more data with `make cwe-index` "
        "(or `python3 scripts/gen_cwe_index.py`). Counts shift; labels rarely disappear.\n"
    )
    out.append("## Contents\n")
    out.append("- [Families](#families) - filter one bug class across all its spellings")
    out.append("- [All labels A-Z](#all-labels-a-z) - exhaustive lookup")
    out.append("- [Known near-duplicates](#known-near-duplicates)")
    out.append("- [Copy-paste filters](#copy-paste-filters)")

    out.append("\n## Families\n")
    out.append(
        "Use the `IN (...)` list to catch every variant. Labels are exact database values, "
        "so copy them verbatim.\n"
    )
    out.append("| Family | Reports | Exact labels |")
    out.append("| --- | ---: | --- |")
    for name, items in ordered:
        labels = "<br>".join(f"`{l}` ({n})" for l, n in items)
        out.append(f"| **{name}** | {sum(n for _, n in items)} | {labels} |")

    out.append("\n## All labels A-Z\n")
    out.append("| Reports | Label | Family |")
    out.append("| ---: | --- | --- |")
    for label, n in sorted(rows, key=lambda x: x[0].lower()):
        out.append(f"| {n} | `{label}` | {family_for(label)} |")

    out.append("\n## Known near-duplicates\n")
    out.append("Same class, different spelling - always filter both sides:\n")
    dupes = [
        ("SSRF", "`Server-Side Request Forgery (SSRF)`", "`Server Side Request Forgery`"),
        ("XSS", "`Cross-site Scripting (XSS) - {Reflected,Stored,DOM,Generic}`", "`Cross-Site Scripting (XSS)`"),
        ("Path traversal", "`Path Traversal`", "`Path Traversal: '.../...//'`"),
        ("Access control", "`Insecure Direct Object Reference (IDOR)`", "`Improper Access Control - Generic`"),
        ("Auth", "`Improper Authentication - Generic`", "`Authentication Bypass by {Spoofing,Capture-replay,Primary Weakness}`"),
        ("Info disclosure", "`Information Disclosure`", "`Information Exposure Through ...` (many)"),
    ]
    out.append("| Class | Label | Variant |")
    out.append("| --- | --- | --- |")
    for cls, a, b in dupes:
        out.append(f"| {cls} | {a} | {b} |")

    out.append("\n## Copy-paste filters\n")
    for cls in ("IDOR / BOLA", "XSS", "SSRF", "SQL injection", "Access control"):
        labels = [l for l, _ in groups.get(cls, [])]
        if labels:
            out.append(f"\n{cls}:\n")
            out.append("```sql")
            out.append(f"SELECT report_id, program, title FROM reports WHERE cwe IN {sql_list(labels)};")
            out.append("```")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {args.out}: {len(rows)} labels in {len(groups)} families")


if __name__ == "__main__":
    main()
