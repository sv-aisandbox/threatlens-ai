# Recorded fixtures

Public data captured on 2026-11-19, used so tests never touch the live network.

| File | Source | Notes |
|---|---|---|
| `nvd/cve-2021-44228.json` | NVD API 2.0 `?cveId=CVE-2021-44228` | Unmodified response (log4j; has NVD `cisa*` fields and CPE configurations) |
| `nvd/page-0.json`, `nvd/page-2.json` | NVD API 2.0 `?resultsPerPage=2&startIndex=0|2&lastModStartDate=...` | Real records. `totalResults` edited from 13 to 4 so the two pages form a complete result set |
| `nvd/page-malformed.json` | Derived from `page-0.json` | One valid record plus two deliberately broken records (bad ID and no descriptions; missing ID) |
| `kev/kev-sample.json` | CISA KEV JSON feed | Four real entries (two with `Known` ransomware use including log4j, two `Unknown`) plus one deliberately malformed entry; `count` edited to match |

Edits are limited to the fields described above. No credentials are involved.
