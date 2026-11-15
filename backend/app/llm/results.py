"""Readers of a stored ① or ② answer that must read both versions of it (DEC-221, card AP-T1).

A run is stored as the schema it was asked for: `triage_v3` / `investigate_v3` before DEC-221, `triage_v4` /
`investigate_v4` after (`llm/templates/output_schemas.json`). Nothing is migrated, so a reader meets both. Two
questions come up in more than one place, and this is where they are answered once:

* **What text does a step list hold?** `next_step_texts`: a version 3 run's `next_steps` is a list of strings, a
  version 4 run's a list of `{step, priority}` rows. The pages that already existed read the strings.
* **What does the case page show of the fields a version 4 run adds?** `timeline_entries`, `timeline_alert_ids`,
  `scope_lists`, `level` (a hypothesis's `likelihood`, a step's `priority`) and `next_step_rows`: each reads the
  stored value as the page serves it - text and closed values only, a version 3 run and a garbled document giving
  less and never an error. They only read; the page-side rules (a row's time from the alert it names, the cap) are
  the view's, `tier2/investigation_view.py`.
* **What may go back into a prompt?** `triage_v3_view` / `investigate_v3_view`: a run cut to the version 3 shape.
  The fields the model writes for the analyst in version 4 (`summary`, `reading_attack`, `reading_benign`,
  `would_change`, `next_checks`; `timeline`, `scope`, a hypothesis's `likelihood`, a step's `priority`) are its words
  about untrusted data, stored and shown as text and never fed back into a prompt (spec 4). A prompt that carries a
  stored run - the case's previous ② result in the dossier, the latest ① or ② result in the knowledge draft - takes
  it through these, so it holds what a version 3 run held, and for a version 3 run exactly that.

The cut is derived from `triage_v3` / `investigate_v3` in `output_schemas.json` (the keys the node names, at every
level), so there is no second list of keys to drift. Pure: no database, no tier import (`llm` may import `security`,
`infra` and `kb` only).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.llm import schemas


def next_step_texts(value: Any) -> list[Any]:
    """The text of each step of an answer's `next_steps`: a string stays itself (version 3), a `{step, priority}`
    row gives its `step` when that is a string (version 4); a row without a text and anything that is not a list
    give nothing. An item that is neither a string nor a row is left as it is, as the pages that read the list
    before version 4 left it."""
    if not isinstance(value, list):
        return []
    texts: list[Any] = []
    for item in value:
        if isinstance(item, Mapping):
            step = item.get("step")
            if isinstance(step, str):
                texts.append(step)
        else:
            texts.append(item)
    return texts


#: The closed values of a hypothesis's `likelihood` and a step's `priority` (`investigate_v4`), as the schema writes
#: them. Anything else a stored document holds is not one of them.
LEVELS = ("low", "medium", "high")


def level(value: Any) -> str | None:
    """`value` when it is one of `LEVELS`, else `None`: the closed set leaves, nothing else (a version 3 run has none)."""
    return value if isinstance(value, str) and value in LEVELS else None


def next_step_rows(value: Any) -> list[dict[str, Any]]:
    """`[{step, priority}]` of an answer's `next_steps`: a version 4 row gives its `step` (a string) and its
    `priority` (`level`, else `None`); a version 3 string is a step with no priority. A row without a text, an item
    that is neither a string nor a row and anything that is not a list give nothing."""
    if not isinstance(value, list):
        return []
    rows: list[dict[str, Any]] = []
    for item in value:
        if isinstance(item, Mapping):
            step = item.get("step")
            if isinstance(step, str):
                rows.append({"step": step, "priority": level(item.get("priority"))})
        elif isinstance(item, str):
            rows.append({"step": item, "priority": None})
    return rows


def scope_lists(value: Any) -> dict[str, list[str]]:
    """`{hosts, accounts}` of an answer's `scope`: the strings of each list, in their order; anything else - no
    `scope` (a version 3 run), a value that is not a mapping, a list that is not one - is an empty list.
    """
    scope = value if isinstance(value, Mapping) else {}
    lists: dict[str, list[str]] = {}
    for key in ("hosts", "accounts"):
        items = scope.get(key)
        lists[key] = (
            [item for item in items if isinstance(item, str)] if isinstance(items, list) else []
        )
    return lists


def timeline_entries(value: Any) -> list[Mapping[str, Any]]:
    """The usable rows of an answer's `timeline`, as stored and in their order: a row that names its alert (a string
    `alert_id`) and says what it shows (a string `what`). Anything else - no `timeline` (a version 3 run), a value
    that is not a list, an item that is not such a row - gives nothing."""
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, Mapping)
        and isinstance(item.get("alert_id"), str)
        and isinstance(item.get("what"), str)
    ]


def timeline_alert_ids(value: Any) -> list[str]:
    """The alert ids the usable rows of `value` name, each once, in the order they first appear."""
    return list(dict.fromkeys(row["alert_id"] for row in timeline_entries(value)))


def _cut(node: Any, value: Any) -> Any:
    """`value` kept to the keys the §6.2 `node` names, at every level; anything the node does not describe is
    returned as it is. A fresh structure: `value` is not changed."""
    if isinstance(node, dict) and isinstance(value, Mapping):
        return {key: _cut(node[key], item) for key, item in value.items() if key in node}
    if isinstance(node, list) and isinstance(value, list):
        return [_cut(node[0], item) for item in value]
    return value


def triage_v3_view(result: Any) -> Any:
    """A stored ① answer (`result` of the proposer's `llm_runs` row) in the `triage_v3` shape: for a version 4 run
    without its five new fields, for a version 3 run equal to itself. Not a mapping: returned as it is.
    """
    if not isinstance(result, Mapping):
        return result
    return _cut(schemas.load()["triage_v3"], result)


def investigate_v3_view(result: Any) -> Any:
    """A stored ② answer in the `investigate_v3` shape: for a version 4 run without `timeline`, `scope` and the
    hypotheses' `likelihood`, and with `next_steps` as the strings of its rows (`next_step_texts`); for a version 3
    run equal to itself. Not a mapping: returned as it is."""
    if not isinstance(result, Mapping):
        return result
    view = _cut(schemas.load()["investigate_v3"], result)
    if "next_steps" in view:
        view["next_steps"] = next_step_texts(view["next_steps"])
    return view
