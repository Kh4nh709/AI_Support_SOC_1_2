# kb/mitre — the local MITRE ATT&CK reference (DEC-223)

`enterprise-attack.json` is a small extract of MITRE's official ATT&CK Enterprise data: for every
technique and sub-technique its id, name, tactics, parent, status, platforms and a short description.
The backend (`backend/app/kb/mitre.py`) reads it from `KB_ROOT/mitre/` (the repo-root `kb/`, mounted
read-only into the app and worker containers) and nothing is ever fetched from the network.

## Source

| | |
|---|---|
| Data | MITRE ATT&CK Enterprise, STIX 2.1 bundle |
| Version | 20.1 (`x_mitre_version`), modified 2026-11-05T15:11:27.678Z |
| File | `enterprise-attack-20.1.json`, 55 277 605 bytes (not in this repository, and never to be) |
| sha256 | `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5` |
| Downloaded from | https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json |
| Downloaded | 2026-11-17, on the Owner's instruction |

The extract's `header` repeats the version, the modified date, the sha256 and the URL, so the file says
what it was made from.

## Copyright and terms

Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The
MITRE Corporation.

ATT&CK is used under MITRE's Terms of Use (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/):
"The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK for
research, development, and commercial purposes. Any copy you make for such purposes is authorized
provided that you reproduce MITRE's copyright designation and this license in any such copy."

The extract carries both in its `header` (`copyright` and `terms`).

## What is in the extract

- `header`: `domain` (`enterprise-attack`), `version`, `modified`, `source_sha256`, `source_url`,
  `copyright`, `terms`, `extracted_by` (`scripts/mitre_extract.py`).
- `techniques`, keyed by ATT&CK id (`T1110`, `T1110.001`), sorted by id. 867 entries: 706 live (479 of
  them sub-techniques), 149 revoked, 12 deprecated. Each has:
  - `name`, `tactics` (ATT&CK's own kill-chain phase names, in its order; 20.1 says `stealth` and
    `defense-impairment` where older versions said `defense-evasion`), `platforms`;
  - `parent`: the id before the dot of a sub-technique, else `null`;
  - `status`: `live`, `revoked` or `deprecated` (kept for tests and later readers, never shown to a model);
  - `description`: the first paragraph of MITRE's own text, cleaned and cut. Citation marks
    `(Citation: ...)` are removed, Markdown links keep only their text, HTML tags such as `<code>` are
    removed, white space is collapsed, and a paragraph over 600 characters is cut on a word boundary
    and ends in ` …` (600 characters at most, the ellipsis included). Nothing is added or reworded;
    placeholders MITRE writes between angle brackets (`<username>`) and its backticks stay.

A revoked or deprecated technique keeps its **own** name, tactics and description. Nothing about what
replaced it is stored (Owner, 17/11): the bundle's `revoked-by` relationships are not read, and MITRE's
deprecation notice (the first paragraph of a deprecated technique, "This technique has been deprecated.
Please use ...") is not used as the description; the next paragraph of MITRE's text is.

Not in the extract: Mobile and ICS techniques, groups, software, mitigations, detections, data sources.

## Regenerating

A new ATT&CK version is a new run of the tool and a new commit; the extract is never edited by hand.

    python3 scripts/mitre_extract.py /path/to/enterprise-attack-<version>.json

The bundle is a path on the machine, never a URL. The output is deterministic: running the tool twice
on one bundle gives the same bytes. `backend/tests/test_kb_mitre.py` pins the header, the 706 live
techniques, that every technique id of `backend/app/ingest/category.py` resolves here with MITRE's text
(229 live, 132 revoked, 11 deprecated on 17/11), and, when the bundle is on the machine, that this file is
exactly what the tool makes of it.
