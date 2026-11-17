# MITRE ATT&CK from a local reference, in the prompts of ① and ②: design

Date: 17/11/2026. Branch: `feature/mitre-local-reference`, cut from `feature/soar-review-web` @ `8c812c7` (what the
trial runs). Trial only for now; `main` and live are not touched. Decision number: DEC-223.

## 1. Intent

An alert often carries MITRE ATT&CK technique ids (`alerts.mitre_ids`, from the rule). Today the ① prompt shows the
ids alone (`mitre: T1110`), and the ② dossier does not show them at all, so whatever the model says about a
technique (its name, its tactic, what it means) comes from the model's memory and can be invented.

The Owner asked (17/11): when an alert has a MITRE id, map it to a MITRE document kept on this machine, extract that
document's text and write it into the prompt, so the model does not make MITRE content up. The data is one official
MITRE set, downloaded once; nothing is fetched from the network at run time.

The ids to map are those of the product's own technique map, `backend/app/ingest/category.py` (Owner, 17/11): its
three technique tables are the vocabulary, and an alert's id is matched the way that module matches it.

## 2. Goals, non-goals, anti-goals

**Goals**
- G1. A local ATT&CK reference in the repository: for every Enterprise technique and sub-technique its id, name,
  tactics, parent, status (live, deprecated or revoked) and a short description, built by a tool from
  the official bundle, with the bundle's version and sha256 recorded.
- G1a. Every technique id of `category.py` (the keys of `WINDOWS_TECHNIQUE_TO_CATEGORY`, `TECHNIQUE_TO_CATEGORY` and
  `EXTENDED_TECHNIQUE_TO_CATEGORY`, 372 distinct ids on 17/11) resolves in the reference to an entry with MITRE's
  text; an id added to those tables later that does not resolve fails a test.
- G2. ① (the proposer prompt): when the alert has MITRE ids, a reference section with the local text of each id.
- G3. ② (the investigation dossier): the same reference for the ids of the case's alerts.
- G4. An id the reference does not hold is said to be absent, in the prompt, instead of being left to the model.
- G5. What the model returns is checked too: a `technique` in ②'s timeline that is not in the reference is marked,
  and a known one is served with the reference's own name.
- G6. A switch, off by default: with it off every prompt is byte for byte what it is today.

**Non-goals**
- Techniques outside Enterprise (Mobile, ICS). Groups, software, mitigations, detections, data sources.
- Translating ATT&CK text into Vietnamese: the reference text is MITRE's English, verbatim after clean-up.
- Showing technique names on the Tier 1 alert page, or anywhere but ②'s timeline (G5).
- Changing the category mapping, the gate, the playbooks or any verdict rule. (One exception, made in review: the gate's
  step 3 refuses a reason whose source is `mitre_reference`, a strengthening that keeps A3 true on three layers; it
  changes no verdict rule.)
- Any run-time download or update job. A new ATT&CK version is a new run of the tool and a new commit.

**Anti-goals** (a result with any of these is a failure)
- A1. A network call to MITRE (or anywhere) from the app, the worker or a test.
- A2. Reference text that is not MITRE's: no sentence written or summarised by a model or by us inside an entry.
- A3. The reference used as evidence about the alert: a `reasons[].quote` taken from it must not pass as a basis for
  the verdict.
- A4. A prompt that changes while the switch is off.
- A5. The 55 MB bundle committed to the repository.

## 3. Constraints

- The official bundle is already on the machine, outside the repository (Owner's go-ahead, 17/11):
  `/project/project/mitre-attack/enterprise-attack-20.1.json`, ATT&CK Enterprise **20.1** (modified 05/11/2026),
  sha256 `539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5`, from
  `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-20.1.json`.
  It holds 867 techniques: 706 live (479 of them sub-techniques), the rest revoked or deprecated.
- ATT&CK is © The MITRE Corporation, used under its Terms of Use: the committed extract carries the copyright line
  and the terms' attribution sentence.
- `kb/` is mounted read-only into the app and worker containers (`./kb:/srv/kb:ro`), so a file under `kb/mitre/` is
  readable there with no compose change.
- Every piece of a ① prompt goes through `PromptBuilder` (a template constant, a `fact()` or a block): the reference
  follows that rule. `output_schemas.json` (context pack §6.2) is a frozen contract and is not changed: the
  reference is not added to the `reasons[].source` values.
- `category.py` (mapping v3.5, the same file on the branch and in the trial checkout) names 372 distinct technique
  ids, most of them parent techniques and many in ATT&CK's numbering from before sub-techniques, because that is
  what the Wazuh rules still carry. Against ATT&CK 20.1: 229 are live, 132 are revoked and 11 are deprecated; none
  is missing. The bundle keeps every revoked or deprecated technique's **own** name, tactics and description (all
  132 revoked ids of the tables have all three), and its `revoked-by` links lead to a live technique (129 in one
  step, 3 in two, such as T1073 → T1574.001).
- Owner, 17/11: a replaced id is described with the old id's own data, not the replacement's, and the replacement
  is not named at all: the id stays the one `category.py` and the rule carry, with MITRE's local text for that id.
- ATT&CK 20.1 names its tactics as it does today: `stealth` and `defense-impairment` stand where older versions
  had `defense-evasion`. The reference keeps MITRE's names as they are (A2); the product's categories are not
  renamed. The reference also keeps the other 477 live ids of 20.1, so an
  id a rule carries that the tables do not name (a sub-technique, mostly) still gets its own text.
- On the trial's real alerts (17/11): 813 carry 1 id, 135 carry 2 to 5, 50 carry 8 or 10; 74 distinct ids, 73 live
  and 1 revoked in 20.1.
- No secret, DSN or lab address in any committed file. Tests never call a model or the network.
- Build by the Director pattern: coders on Sonnet 5.5 in their own worktrees, reviews on Opus 5.5.

## 4. The local reference

**4.1 The tool.** `scripts/mitre_extract.py BUNDLE [--out kb/mitre/enterprise-attack.json]` reads the bundle from a
path given on the command line (never a URL) and writes the extract. It refuses a file that is not an ATT&CK
Enterprise bundle. The output is deterministic (sorted by id, stable JSON), so running it twice on one bundle gives
the same bytes.

**4.2 The extract** `kb/mitre/enterprise-attack.json`:
- a header: `domain` (`enterprise-attack`), `version` (`20.1`), `modified`, `source_sha256`, `source_url`,
  `copyright` and `terms` (MITRE's lines), `extracted_by` (the tool's name);
- `techniques`, keyed by id (`T1110`, `T1110.001`): `name`, `tactics` (the kill-chain phase names, ATT&CK's own
  spelling, in ATT&CK's order), `parent` (the parent id of a sub-technique, else null), `status` (`live`,
  `deprecated` or `revoked`: kept for the tests and for a later reader, never shown to the model), `platforms`, and
  `description`.
- `description` is the first paragraph of MITRE's description, cleaned: citation marks `(Citation: …)` removed,
  Markdown links reduced to their text, HTML tags such as `<code>` removed, white space collapsed. It is cut at
  600 characters on a word boundary with ` …` when longer (median first paragraph 438 characters, 90 % under 722).
  Nothing is added or reworded (A2).

**4.3 The loader.** `backend/app/kb/mitre.py`: loads the extract once per process (as `kb/lookup.py` does with the
playbooks), checks its header and shape, and answers `lookup(id)` in the two steps `category.py`'s tiers use: the
exact id first, then its parent (`T1059.003` → `T1059`) when the exact id is not in the reference. A revoked or
deprecated id answers with **its own entry** (its own name, tactics and description), exactly like a live one: the
`revoked-by` links of the bundle are not followed and not stored. The answer says how it was found (exact or
parent), so the prompt can show it. A missing or malformed file is not an error of the alert: the loader reports "no reference", the prompt is built
without the section and the run carries the warning `mitre_reference_unavailable`.

## 5. ① the proposer prompt

With `PROMPT_INCLUDE_MITRE_REFERENCE` on and at least one valid id on the alert, a section follows the playbook
section and comes before the learned (RAG) section:

- its heading and two fixed sentences (template constants, Vietnamese like the rest of the prompt): the text below
  is quoted from the local MITRE ATT&CK document, version N; say about a technique only what this text says; it
  describes techniques in general and is not evidence about this alert, so do not quote it in `reasons`;
- one block, source `mitre_reference`, holding one entry per id in the alert's own order, at most **6** entries:
  `<id> <name>`, a sub-technique's parent as `sub-technique of <parent id> <parent name>`, `tactics: …`, then the
  description. A revoked or deprecated id is shown like any other, with its own name, tactics and description and
  no word about its status or its replacement; an id found through its parent says `<id>: not in the reference, parent <parent id>` and shows the
  parent's entry;
- ids beyond the sixth are listed on one line each as `<id> <name>` with no description;
- an id that passes the id pattern but is not in the reference: the line `<id>: not in the local ATT&CK reference`
  (G4) and the warning `mitre_unknown_id` on the run. An id that fails the pattern is dropped as today
  (`invalid_mitre_id`).

The block is reference material, not evidence: `mitre_reference` is not among the sources a reason may name, so a
reason that cites it does not survive the output contract (A3). The injection detector does not report findings on
this block: it is our own vetted file, not alert data.

The token budget cuts this section first, before the learned section (`mitre_reference_dropped`): it is the least
specific material in the prompt. With six entries it is about 1 500 tokens of a 40 000 budget.

The verifier's prompt is not changed.

## 6. ② the investigation dossier

With the switch on, the dossier gains one reference section: the distinct valid ids of the case's alerts, most
frequent first, at most **10** entries, the same entry format, the same heading and first sentence, a closing sentence of its
own naming ②'s field (`evidence[].quote`) in place of ①'s `reasons`, and the same line for an unknown id. The dossier's own budget drops this section before any alert material. No id on any alert: no section.

## 7. What the model returns (G5)

②'s `timeline[].technique` is free text from the model. When the result is served (`tier2/investigation_view`):
- a value that names an id in the reference is served with `technique_name`, the reference's name, and
  `technique_known: true`;
- a value that has the shape of an id and is not in the reference is served with `technique_known: false`, and the
  run's checks carry `technique_not_in_reference` with the count;
- anything else (empty, null, prose) is served as today.

The Tier 2 timeline shows a known technique as `<id> · <name>` and an unknown one with a short note that it is not
in the local ATT&CK document. Nothing is rewritten in what the model stored.

① returns no technique, so there is nothing to check there.

## 8. The switch and the record

- `PROMPT_INCLUDE_MITRE_REFERENCE` (boolean, default **false**), read by ① and ②. The trial's `.env` sets it true.
- A run whose prompt carried the section says so in its stored warnings/trace (`mitre_reference:<version>`), so runs
  with and without it can be told apart later. The system prompt templates are not edited, so `prompt_version`
  changes only with the commit.
- Evaluation note: the gold v2 figures of 13–14/11 were measured without this section; a run with the switch on is a
  different configuration and is not comparable without re-measuring.

## 9. Tests

- The tool: a small hand-made bundle (live, sub-technique, deprecated, revoked with and without a replacement, a
  description with citations, links and tags, one longer than 600 characters) gives the expected extract; a file
  that is not an ATT&CK bundle is refused; two runs give the same bytes; the committed extract matches its header
  (706 live techniques, version 20.1, the sha256 above).
- The loader: lookup of a live id, a sub-technique with its parent, a revoked id and a deprecated id each answered
  with its own text and nothing of a replacement, an id found only through its parent, an unknown id, a missing file, a malformed file.
- `category.py` (G1a): every key of its three technique tables resolves in the committed extract to an entry with a
  non-empty description of its own; the counts of 17/11 are pinned (229 live, 132 revoked, 11 deprecated).
- ①: switch off → the prompt is byte-identical to today's (existing prompt tests stay green untouched); switch on →
  the section, the order, the 6-entry cap, the unknown-id line and warning, the budget cut first, no section without
  ids, the linter passes, a reason citing `mitre_reference` does not pass, the detector reports nothing for the block.
- ②: the section in the dossier, the 10-entry cap, off → dossier unchanged.
- The view: known, unknown and non-id `technique` values; the UI shows the name or the note.
- No test opens a socket.

## 10. Deploying on the trial (Owner)

The `ui` is a built image, not a mount, and this feature changes `backend/app`, `kb/` and `frontend/`: the backend is
recreated and restarted and the `ui` rebuilt (a `ui` that is not rebuilt leaves the timeline without the technique names
and without the "not in the document" note).

1. Merge the branch into what the trial checkout runs (the Director prepares it; the trial checkout is detached at
   `8c812c7` today).
2. Add `PROMPT_INCLUDE_MITRE_REFERENCE=true` to the trial's `.env`.
3. From the trial checkout: `docker compose up -d --force-recreate app worker` (an `.env` change needs
   `--force-recreate`, not `restart`; `backend/app` and `kb/` are live mounts, so the recreate starts the merged code).
4. `docker compose restart rag-worker` (a merge under `backend/app` needs it, DEC-099).
5. `docker compose up -d --build ui` (the trial's `ui` binds two addresses: the second must be up first, as in the
   runbook's Voyage steps).
6. Check: `docker compose ps app worker rag-worker ui` all `Up` and `printenv PROMPT_INCLUDE_MITRE_REFERENCE` in `worker`
   prints `true`; open a new alert that has a MITRE id and look at its ① run for the `mitre_reference:20.1` mark; on a case
   page, the **Diễn biến** tab shows `<id> · <name>` (after step 5).
No migration: the feature has no table. The runbook's section "MITRE ATT&CK reference (DEC-223)" has the commands.

## 11. Left to the builder

The module and function names beyond those given, the exact Vietnamese wording of the heading and the two
sentences, how the dossier collects the case's ids, where the run's trace keeps the mark, and the UI detail of the
timeline note. Decisions the builder makes go in the plan's ledger as rulings.
