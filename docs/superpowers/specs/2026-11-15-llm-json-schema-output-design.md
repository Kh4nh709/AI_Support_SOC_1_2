# ① asks the provider to enforce the output schema (`json_schema`) — design

Date: 2026-11-15 · Trial only (branch `director/trial-binary-verdict`, on top of `f47faf8`;
never merged into `main`) · Decision: DEC-218

## 1 · Why

On the trial (all ① proposer runs to 15/11, model `glm-5.3` through `api.z.ai`), the first call
fails the `triage_v3` schema in 8.0 % of runs: 2,427 valid at once, 191 valid after the one repair
call, 19 failed for good (the alert ends `unavailable`). 16 of those 19 carry
`reasones: unexpected key`: the model misspells the key `reasons`. The repair round cannot fix
that: it is a fresh call that does not show the model its previous answer, and an unexpected key
is reported without its name (`- <root>: unexpected key`, planning decision 9).

Today every call sends `response_format: {"type": "json_object"}`: the provider guarantees JSON,
not the shape. The Owner's request (15/11): **"Fix lỗi này bằng cách ép schema cụ thể cho LLM trả
về đúng khung."**

Measured before building (the Director, 15/11, read-only, 20 calls):

- `response_format: {"type": "json_schema", "json_schema": {"name", "strict": true, "schema"}}`
  is accepted by `api.z.ai` for `glm-5.3` and obeyed even against a prompt that asks for other
  keys (the prompt asked for `ket_luan` and `reasones`; the reply had `verdict` and `reasons`).
- On 8 stored prompts whose runs had failed with `reasones`: `json_schema` gave 8 of 8
  schema-valid answers; `json_object` gave 7 of 8 (the eighth was `reasones` again).
- The provider's documentation names only `json_object`, so this behaviour is not promised.
  DeepSeek (the live stack's provider) documents only `json_object` too.

## 2 · Goals, non-goals

Goals

- G1. When the switch is on, ①'s proposer and verifier calls (first call and repair call) send
  the JSON Schema of the schema they are validated against.
- G2. One source of truth: the JSON Schema is generated from
  `backend/app/llm/templates/output_schemas.json`, never written by hand a second time.
- G3. Off by default; with the switch off the request is byte for byte today's.
- G4. A provider that refuses the format does not stop ①: the call falls back to `json_object`
  and the run records that it did.
- G5. The first call's validation errors are kept, so the next measurement knows what a repaired
  run got wrong.

Non-goals

- The prompts: `backend/app/llm/templates/*`, the builder sections of `llm/triage.py`, the
  rendered schema text. `prompt_version` must not move.
- The validator (`schemas.validate`), `normalise` and the repair round: unchanged, they stay as
  the check behind the provider.
- ② (`llm/investigate.py`) and the RAG drafter. Same idea, later.
- Tool calling as a second mechanism.

## 3 · The converter (`backend/app/llm/schemas.py`)

`json_schema(name) -> dict`: the JSON Schema of a named schema, built from the compact notation
that module already interprets (its docstring is the table):

| compact value | JSON Schema |
| --- | --- |
| `{...}` | `{"type": "object", "properties": …, "required": [every key, in file order], "additionalProperties": false}` |
| `[x]` | `{"type": "array", "items": <x>}`, plus `"minItems": 1` where the notation says so |
| enum `"a\|b\|c"` | `{"type": "string", "enum": [...]}`; with `null` among the alternatives `{"type": ["string", "null"], "enum": [..., null]}` |
| `"string"` and a free string with a note | `{"type": "string"}` |
| `"string\|null"` | `{"type": ["string", "null"]}` |
| `0` | `{"type": "integer"}` |
| `true` / `false` | `{"type": "boolean"}` |

`structured_basis.identity_privileged` stays the string enum `true|false|unknown` (the validator's
`normalise` already turns a JSON boolean into the string).

The result for `triage_v3` must equal the schema the Director probed with; it is in section 7 and
a test pins it.

## 4 · The switch (`backend/app/infra/config.py`)

`LLM_RESPONSE_FORMAT`: `json_object` (default) or `json_schema`; any other value is a
configuration error at load, like the module's other closed-set keys. It goes in `.env.example`
and in the runbook's environment table (a test pins both lists).

## 5 · The calls (`backend/app/llm/triage.py`: `_call`, `propose`, `verify`; `llm/adapter.py`)

- With the switch on, both calls of `_call` pass
  `response_format={"type": "json_schema", "json_schema": {"name": <schema name>, "strict": true, "schema": schemas.json_schema(<schema name>)}}`.
  With it off, nothing is passed and the adapter sends `json_object` as today.
- Fallback (G4), in the adapter, which sees the provider's answer: when a `json_schema` request is
  refused with HTTP 400 or 422, the same request is sent once more with `json_object`, and the
  result says which format produced it (`LLMResult.response_format`). Every other failure is
  classified as today. The fallback is per call: nothing is remembered.
- A run in which a call fell back carries the warning `response_format_fallback` in the proposer
  row's `citation_warnings` (the list that already carries the builder's warnings), and the
  adapter's log line names the outcome.
- `Proposal` gains `first_errors: list[str]`: the first call's validator messages (`[]` when the
  first call was valid).

## 6 · What is stored (G5)

- `gate_result.step1_errors` (a run that reached the gate): the first call's validator messages
  when step 1 was `repaired`, else `[]`.
- The `stopped_by = 'schema'` row's `gate_result` keeps `schema_errors` (the last call's) and
  gains `first_errors`.
- These messages may name a key the model invented (`reasones: unexpected key`). They are stored,
  as `schema_errors` already is; they are never put in a prompt. The blind arm does not see
  `gate_result`.

## 7 · The pinned `triage_v3` schema

```json
{"type": "object", "additionalProperties": false,
 "required": ["suggested_action", "confidence", "structured_basis", "reasons", "playbook_used"],
 "properties": {
  "suggested_action": {"type": "string", "enum": ["false_positive", "true_positive"]},
  "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
  "structured_basis": {"type": "object", "additionalProperties": false,
   "required": ["severity", "ioc_reputation", "asset_criticality", "identity_privileged", "occurrence_count", "playbook_rule_applied"],
   "properties": {
    "severity": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
    "ioc_reputation": {"type": "string", "enum": ["malicious", "suspicious", "clean", "not_found", "skipped"]},
    "asset_criticality": {"type": "string", "enum": ["high", "medium", "low", "unknown"]},
    "identity_privileged": {"type": "string", "enum": ["true", "false", "unknown"]},
    "occurrence_count": {"type": "integer"},
    "playbook_rule_applied": {"type": ["string", "null"]}}},
  "reasons": {"type": "array", "items": {"type": "object", "additionalProperties": false,
   "required": ["claim", "quote", "source"],
   "properties": {
    "claim": {"type": "string"}, "quote": {"type": "string"},
    "source": {"type": "string", "enum": ["wazuh_raw_log", "rule_description", "correlation_samples", "kb_playbook", "context", "siem_context"]}}}},
  "playbook_used": {"type": ["string", "null"]}}}
```

(Key order inside an object does not matter for the comparison; the order of `required` and of
each `enum` follows the file.)

## 8 · Tests

Red first, then green:

- the converter: `json_schema("triage_v3")` equals section 7; `verifier_v2` is converted; every
  schema in the file converts; a walk of the compact schema and the generated one side by side
  (every object lists all its keys as required and forbids others; every enum has the file's
  values);
- the switch: default `json_object`; `json_schema` accepted; another value refused;
  `.env.example` and the runbook table list it;
- `_call`: with the switch on, the proposer's and the verifier's first call and repair call each
  carry the format with the right schema name; with it off, `response_format` is not passed;
- the adapter: a 400 and a 422 on a `json_schema` request are retried once with `json_object`
  and the result says so; a 400 on a `json_object` request is still permanent; a 429, 402, 5xx
  and a timeout on a `json_schema` request behave as today;
- the warning `response_format_fallback` reaches the proposer row; `step1_errors` and
  `first_errors` are stored as section 6 says (db tests; written, listed, not run:
  `TEST_DATABASE_URL` does not authenticate on this host).

`make lint` and `make test` green. No frontend change.

## 9 · Deploy (the Owner)

`LLM_RESPONSE_FORMAT=json_schema` in the trial `.env`, then recreate the containers that read it:
`docker compose up -d --force-recreate app worker rag-worker`. A `restart` does not apply an `.env`
edit (`.env` is read when a container is created). Check:
`docker compose exec -T app printenv LLM_RESPONSE_FORMAT` → `json_schema`. The live stack keeps the
default.

After the deploy, the measure is the share of proposer runs whose `gate_result.steps["1"]` is
`repaired` and the count of `stopped_by = 'schema'` rows, against 8.0 % and 0.7 % before.
