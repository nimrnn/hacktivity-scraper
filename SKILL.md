---
name: hacktivity-skill-builder
description: Build a vulnerability-hunting SKILL.md (checklists, techniques, edge cases, bypasses, payload patterns) from a local database of disclosed HackerOne reports. Use whenever the user wants to create, extend, or improve an agent skill for hunting a specific bug class (IDOR, SSRF, XSS, SQLi, race conditions, business logic, etc.), asks what techniques researchers used for a vulnerability type, or wants real-world report evidence turned into hunting guidance. Also use when the user mentions hacktivity-scraper, reports.sqlite, or asks to mine disclosed reports.
---

# HackerOne Report → Hunting Skill

Turn disclosed HackerOne reports into a practical skill an agent can follow while hunting: what to try, where to look, which edge cases break naive checks, and how to confirm a finding is real.

The value here is evidence. Every technique, parameter pattern, and bypass you put in the output skill should trace back to reports in the database. A skill full of generic OWASP advice is worthless to an agent that already knows OWASP; specific, observed behavior is what helps.

## Step 0 — Get the database (do this first)

The data lives in `reports.sqlite` inside the `hacktivity-scraper` checkout.

1. Look for an existing database first, in this order:
   - a path the user named explicitly
   - `./reports.sqlite`
   - `$HACKTIVITY_DB` if set
   - `../hacktivity-scraper/reports.sqlite`
   - `~/projects/hacktivity-scraper/reports.sqlite`
2. If one exists, **use it as-is**. Do not re-scrape, do not "refresh" it, do not delete it. It is the user's dataset and re-downloading it can take hours. Only scrape when the user explicitly asks for fresh data.
3. If none exists, build it:

   ```bash
   cd hacktivity-scraper
   export H1_USERNAME=...   # HackerOne username
   export H1_TOKEN=...      # API token from hackerone.com/settings/api_token
   go run ./cmd/scraper -from-date 2020-01-01
   ```

   Credentials are required. If `H1_USERNAME` / `H1_TOKEN` are not set, ask the user for them (or ask them to export them) rather than guessing. Tell them a full run over several years can take a long time, and that Ctrl+C is safe: finished reports stay in the database and a later run resumes where it left off.

Verify before proceeding:

```bash
sqlite3 reports.sqlite "SELECT COUNT(*) FROM reports;"
```

If the count is 0, the scrape did not produce data - fix that before writing any skill.

## Step 1 — Understand the data

```sql
CREATE TABLE reports (
  report_id INTEGER PRIMARY KEY,   -- also roughly chronological
  cwe       TEXT NOT NULL,         -- human-readable, NOT a CWE number
  title     TEXT NOT NULL,
  cve       TEXT NOT NULL,         -- JSON array string, e.g. '["CVE-2024-1234"]'
  url       TEXT NOT NULL,
  program   TEXT NOT NULL,
  markdown  TEXT NOT NULL          -- full vulnerability_information body
);
```

Things that will bite you if you assume otherwise:

- **`cwe` is a label, not an ID.** Values look like `Insecure Direct Object Reference (IDOR)` or `Cross-site Scripting (XSS) - Stored`. There is no `CWE-639` column. Match with `LIKE`, and group first to see the exact spellings.
- **XSS is split across variants**: `Reflected`, `Stored`, `DOM`, `Generic`. A filter for just "XSS" silently loses most rows.
- **Some rows have `cwe = ''`** - the report was never classified. They are still usable by title, but don't count on the filter.
- **`markdown` can be empty** even when metadata exists (body fetch failed or the report has no writeup). Filter with `length(markdown) > 500` when you need substance.
- **`cve` is a JSON string**, so compare with `cve != '[]'` rather than checking for NULL.
- Report bodies contain redaction blocks (`██████`) for hosts and endpoints. Do not invent the missing values.

## Step 2 — Pick and size the target bug class

Don't rediscover the label list. It is already curated in `references/cwe-index.md` (same directory as this skill, or in the `hacktivity-scraper` checkout): every distinct label, deduplicated, grouped into families, with counts, near-duplicate aliases, and ready-made `IN (...)` filters.

Read that file first, then:

1. Find the family matching the user's request (IDOR/BOLA, XSS, SSRF, SQL injection, access control, etc.).
2. Use its exact labels in a single `IN (...)` filter instead of several `LIKE`s. That catches the spelling variants (`Server Side Request Forgery` vs `Server-Side Request Forgery (SSRF)`, the four XSS variants) without guessing.
3. If the request spans families (e.g. "account takeover"), combine the relevant families' labels rather than widening to everything.
4. Trust the filter over the family name: if a label looks misfiled, filter by the label itself.

Check the index is still fresh. The header records a snapshot count; compare it with the live database:

```bash
sqlite3 'file:reports.sqlite?mode=ro' "SELECT COUNT(*) FROM reports;"
```

If the database has grown noticeably since that snapshot, regenerate before relying on counts, and look for labels that did not exist when the index was written:

```bash
cd hacktivity-scraper && make cwe-index
sqlite3 -header -column 'file:reports.sqlite?mode=ro' \
  "SELECT cwe, COUNT(*) AS n FROM reports WHERE cwe != '' GROUP BY cwe ORDER BY n DESC LIMIT 40;"
```

If the index file is missing, fall back to that discovery query. Either way, count before reading: if the class has fewer than ~15 usable reports, widen to the family or add adjacent labels and say so in the output skill; do not pad the skill with generic filler to hide thin evidence.

## Step 3 — Read reports without blowing up context

Bodies average ~2 KB but reach 80 KB+. Never `SELECT markdown` for hundreds of rows into the terminal. Select a bounded, deduplicated sample and write bodies to files, then read them selectively.

```bash
mkdir -p /tmp/h1
sqlite3 reports.sqlite \
  "SELECT report_id FROM reports
   WHERE cwe LIKE '%IDOR%' AND length(markdown) > 800
   ORDER BY report_id DESC LIMIT 40;" > /tmp/h1/ids.txt

while read -r id; do
  sqlite3 reports.sqlite "
    SELECT '# Report ' || report_id || ' - ' || title || ' (' || program || ')' || char(10) ||
           'URL: ' || url || char(10) || char(10) || markdown
    FROM reports WHERE report_id = $id;" > "/tmp/h1/$id.md"
done < /tmp/h1/ids.txt
```

Then read a handful of files per batch (start with 5-8), and only continue if new patterns are still appearing. Stop when two batches in a row add nothing - that is the signal the class is saturated, not that you need more rows.

Sampling tips:

- Mix recent and older: `ORDER BY report_id DESC` for modern stacks and current program behavior, `ASC` for classic techniques.
- Skip near-duplicate titles from the same program (`GROUP BY program` mentally) - one program often files five reports for one root cause.
- Prefer longer bodies when you need methodology, shorter ones when you need impact statements.
- If a program dominates the sample (`deptofdefense`, `curl`, `nextcloud`, `shopify` appear often), cap it so one codebase doesn't define the whole skill.

## Step 4 — Extract, don't summarize

While reading, mine for concrete, reusable material:

- **Attack surface clues**: endpoint shapes, parameter names, ID formats, headers, object relationships (`/api/v1/orgs/{id}/members`).
- **Prerequisite conditions**: needs an org, a second account, a specific role, an invite flow, a mobile client, an unauthenticated route.
- **Technique and bypass patterns**: ID swapping, UUID vs sequential, nested object references, method swaps (`GET`→`PUT`), content-type confusion, parameter pollution, hidden fields, batch/bulk endpoints, GraphQL node IDs, websocket channels, export/report endpoints.
- **What the naive check misses**: ownership checked on the parent but not the child, authorization on read but not write, UI-only restrictions, checks that trust a client-supplied tenant/org ID.
- **Signal of confirmation**: what the researcher observed that proved impact (another tenant's PII, a write that persisted, a callback hit).
- **Edge cases and dead ends**: reported-but-invalid variants, WAF behavior, rate limits, scope restrictions.

Ignore: pleasantries, program-specific policy text, generic vulnerability definitions copied into the report, and long remediation sections.

Keep a running evidence list as you go: `report_id`, what it demonstrated, one line each. You will cite these in the output skill.

## Step 5 — Write the skill

Put the generated skill where the user wants it (`skills/<name>/SKILL.md` by default) with YAML frontmatter:

```markdown
---
name: hunting-<bug-class>
description: <what it does + pushy "use this whenever..." triggering conditions>
---
```

Then follow this structure, adapting section names to the bug class:

1. **When to use** - the bug class and the request shapes that should trigger it.
2. **Recon / entry points** - where this class hides, with concrete endpoint and parameter patterns.
3. **Testing workflow** - ordered, actionable steps an agent can execute (create two accounts, capture request, swap identifier, compare responses, check side effects).
4. **Technique catalogue** - each technique as: what to do, why it works, example request shape, what confirms it. Group by mechanism, not by report.
5. **Edge cases and bypasses** - the list that makes the skill worth having.
6. **False positives and limits** - what looks like a hit but isn't, plus scope/legal reminders.
7. **Evidence** - `report_id` + program + one-line finding for the reports that shaped each section.

Writing rules:

- Prefer checklists and short imperative steps over prose.
- One technique per bullet; no "also consider" grab bags.
- Every non-obvious claim carries a `report_id` reference. If you cannot trace it, cut it.
- Never fabricate endpoints, parameter names, or payloads. Use placeholders (`{victim_id}`) where the report redacted values.
- Include the variant taxonomy you observed (e.g. stored vs reflected vs DOM) so the agent tests the right things.
- Keep the generated skill under ~400 lines. Link to `/tmp/h1/<report_id>.md` files rather than pasting long report excerpts.
- Note the dataset's coverage honestly: date range, report count for that class, and which programs dominate, so the user knows the skill's blind spots.

Finish by reporting: how many reports matched, how many you actually read, the techniques you extracted, and anything you deliberately left out for lack of evidence.

## Guardrails

- This is for authorized security testing, bug bounty programs within scope, and writing internal guidance. Never use extracted payloads against systems the user does not have permission to test.
- Redacted hosts and endpoints stay redacted.
- Do not modify or delete the user's `reports.sqlite`. Read-only queries only (`sqlite3 'file:reports.sqlite?mode=ro'`) when you just need data; let the scraper own writes.
- If a class has almost no reports in the database, say so instead of writing an unsupported skill. Offer to scrape more data (with the user's go-ahead) or narrow the scope.
