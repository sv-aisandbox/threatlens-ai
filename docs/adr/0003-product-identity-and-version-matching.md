# ADR 0003 - Product identity and version matching

- Status: Accepted
- Date: 2026-11-19

## Context
Spec section 20.4: a matching product name is not a confirmed vulnerable asset; every match needs a recorded source and reason; unclear cases return `unknown`. NVD publishes affected products as CPE 2.3 match criteria with optional version-range operators (`versionStartIncluding`, `versionStartExcluding`, `versionEndIncluding`, `versionEndExcluding`). Wrongly saying "confirmed" is the most damaging error this system can make, so every rule below errs toward the weaker status.

## Decision

### Statuses (written on `Software -[:AFFECTED_BY]-> Vulnerability`)
| Status | Meaning |
|---|---|
| `confirmed` | Product identity established by CPE vendor and product, and the installed version is inside an affected range or equals an affected version, with no unverified condition |
| `possible` | Identity and version point to affected, but a condition is unverified (see caps) |
| `not_affected` | The CVE names this product, and the installed version is outside every affected range |
| `unknown` | The CVE names this product, but the installed version is missing or cannot be compared |

If the CVE does not name the product at all, **no edge is written**. Absence of an edge is not a claim of safety, and a CVE with no `configurations` yet (for example "Awaiting Analysis") produces no edge.

### Identity
1. If the inventory entry has a CPE 2.3 string, identity is its vendor and product (lower-cased, escapes removed). Otherwise identity is the normalized vendor and product names.
2. Name normalization: lower-case, runs of non-alphanumerics become `_`, trailing corporate suffix words on the vendor (`inc`, `corp`, `corporation`, `ltd`, `limited`, `llc`, `gmbh`, `co`, `company`) are dropped. Nothing smarter: no fuzzy matching and no vendor alias tables. "Apache Software Foundation" does not equal `apache`.
3. Original vendor, product, version and CPE strings are always kept on the `Software` node.
4. Criteria with a wildcard (`*`) or not-applicable (`-`) vendor or product are ignored.

### Which criteria are considered
Only `cpeMatch` entries with `vulnerable: true`. Entries with `vulnerable: false` describe platforms and are ignored.

### Version comparison
- A version is comparable only if it is dotted numbers (`^\d+(\.\d+){0,5}$`), compared numerically and zero-padded (`1.0` equals `1.0.0`).
- Anything else (`1.2.3p1`, `2.0-beta`, `8.0.1-r2`, dates, epochs) is **not comparable**, and the result is `unknown`. There is no ecosystem-specific guessing (no PEP 440, no Debian or RPM rules) until such rules are specified and tested per ecosystem.
- Criteria version `*` with bounds: the installed version must satisfy every bound present. Without bounds: all versions are affected.
- Criteria with a specific version: equal after numeric comparison means affected, different means not affected. If either side is not comparable the result is `unknown`, unless the strings are identical.
- Installed version missing: `unknown`.

### Caps: `confirmed` becomes `possible` when
- identity came from names only (no inventory CPE);
- the match sits in an `AND` configuration with other nodes or an `AND` node with several matches (a platform or companion condition is not verified);
- the node is negated (not evaluated);
- the criteria restrict `update`, `edition`, `language`, `sw_edition`, `target_sw`, `target_hw` or `other` to a specific value while the inventory does not record the same value. If the inventory records a different value, that criteria entry does not apply.

### Aggregation across entries
Any uncapped in-range entry gives `confirmed`; otherwise any in-range entry gives `possible`; otherwise any non-comparable entry gives `unknown`; otherwise `not_affected`.

### Provenance
Every edge records `matched_by` (`cpe-matcher/1`), `matched_at`, `match_reason` (human-readable, includes the range or the reason it is unknown) and `source_ref` (the NVD Evidence ID). The matcher only removes edges it created itself (`matched_by = cpe-matcher/1`).

## Consequences
- Many real-world version formats yield `unknown` by design; that is visible and countable, not silently wrong.
- Only `confirmed` counts as exposure in answers.
- Ecosystem-specific comparison can be added later as separately tested strategies without changing the status model.
- Candidate selection scans `Vulnerability.configurations_json`; an index over CPE vendor and product will be needed at full NVD scale.
