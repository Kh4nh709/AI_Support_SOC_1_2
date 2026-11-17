"""`app.kb.mitre` — the loader of the local ATT&CK reference (DEC-223 T1, spec §4.3 and G1a).

Two parts: the loader on small extracts written to a temp directory (live, sub-technique, revoked
and deprecated answered with their own text, the parent fallback, an unknown id, a missing or a
malformed file, the once-per-process cache), and the committed extract itself (ATT&CK 20.1: its
header, its 706 live techniques, and every technique id of `ingest/category.py` resolving to MITRE's
text, so an id added to those tables later that the reference lacks fails here).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import sys

import pytest
from app.ingest import category
from app.kb import mitre
from app.kb.lookup import KB_ROOT

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
COMMITTED = REPO_ROOT / "kb" / "mitre" / "enterprise-attack.json"
BUNDLE = pathlib.Path("/project/project/mitre-attack/enterprise-attack-20.1.json")
BUNDLE_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
BUNDLE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-20.1.json"
)


@pytest.fixture(autouse=True)
def _fresh_cache():
    mitre.reset_cache()
    yield
    mitre.reset_cache()


def _entry(name, description, *, tactics=("credential-access",), parent=None, status="live"):
    return {
        "name": name,
        "tactics": list(tactics),
        "parent": parent,
        "status": status,
        "platforms": ["Windows"],
        "description": description,
    }


def _extract(techniques=None, **header_overrides) -> dict:
    header = {
        "domain": "enterprise-attack",
        "version": "9.9",
        "modified": "2026-11-05T15:11:27.678Z",
        "source_sha256": "a" * 64,
        "source_url": "https://example.invalid/x.json",
        "copyright": "c",
        "terms": "t",
        "extracted_by": "scripts/mitre_extract.py",
    }
    header.update(header_overrides)
    if techniques is None:
        techniques = {
            "T1110": _entry("Brute Force", "Brute force text."),
            "T1110.001": _entry("Password Guessing", "Guessing text.", parent="T1110"),
            "T1073": _entry(
                "DLL Side-Loading", "Old text.", tactics=("persistence",), status="revoked"
            ),
            "T1064": _entry(
                "Scripting", "Scripts text.", tactics=("stealth", "execution"), status="deprecated"
            ),
            "T1059": _entry("Command and Scripting Interpreter", "Interpreter text."),
        }
    return {"header": header, "techniques": techniques}


def _write(tmp_path: pathlib.Path, extract: dict | str, name: str = "e.json") -> pathlib.Path:
    path = tmp_path / name
    path.write_text(
        extract if isinstance(extract, str) else json.dumps(extract, ensure_ascii=False),
        encoding="utf-8",
    )
    return path


# --- the module's constants and types -----------------------------------------------------------


def test_mitre_file_is_under_the_kb_root():
    assert mitre.MITRE_FILE == KB_ROOT / "mitre" / "enterprise-attack.json"
    assert mitre.MITRE_FILE == COMMITTED


def test_description_cap_is_600_and_the_tool_agrees():
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import mitre_extract

    assert mitre.DESCRIPTION_MAX_CHARS == 600
    assert mitre_extract.DESCRIPTION_MAX_CHARS == mitre.DESCRIPTION_MAX_CHARS


def test_entry_and_found_are_frozen_dataclasses(tmp_path):
    path = _write(tmp_path, _extract())
    found = mitre.lookup("T1110", path=path)
    assert found is not None
    assert dataclasses.is_dataclass(found) and dataclasses.is_dataclass(found.entry)
    with pytest.raises(dataclasses.FrozenInstanceError):
        found.via = "parent"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        found.entry.name = "x"  # type: ignore[misc]
    assert isinstance(found.entry.tactics, tuple)
    assert [f.name for f in dataclasses.fields(mitre.Entry)] == [
        "id",
        "name",
        "tactics",
        "parent",
        "status",
        "description",
    ]
    assert [f.name for f in dataclasses.fields(mitre.Found)] == ["entry", "via"]


# --- lookup ---------------------------------------------------------------------------------------


def test_lookup_a_live_technique_exactly(tmp_path):
    found = mitre.lookup("T1110", path=_write(tmp_path, _extract()))
    assert found == mitre.Found(
        entry=mitre.Entry(
            id="T1110",
            name="Brute Force",
            tactics=("credential-access",),
            parent=None,
            status="live",
            description="Brute force text.",
        ),
        via="exact",
    )


def test_lookup_a_sub_technique_carries_its_parent_id(tmp_path):
    found = mitre.lookup("T1110.001", path=_write(tmp_path, _extract()))
    assert found is not None and found.via == "exact"
    assert found.entry.id == "T1110.001"
    assert found.entry.parent == "T1110"
    assert found.entry.name == "Password Guessing"


def test_a_revoked_id_is_answered_with_its_own_text(tmp_path):
    found = mitre.lookup("T1073", path=_write(tmp_path, _extract()))
    assert found is not None and found.via == "exact"
    assert (found.entry.id, found.entry.name, found.entry.tactics) == (
        "T1073",
        "DLL Side-Loading",
        ("persistence",),
    )
    assert found.entry.description == "Old text."
    assert found.entry.status == "revoked"


def test_a_deprecated_id_is_answered_with_its_own_text(tmp_path):
    found = mitre.lookup("T1064", path=_write(tmp_path, _extract()))
    assert found is not None and found.via == "exact"
    assert found.entry.name == "Scripting"
    assert found.entry.tactics == ("stealth", "execution")
    assert found.entry.description == "Scripts text."
    assert found.entry.status == "deprecated"


def test_an_id_found_only_through_its_parent(tmp_path):
    # T1059.003 is not in this extract; its parent T1059 is.
    found = mitre.lookup("T1059.003", path=_write(tmp_path, _extract()))
    assert found is not None
    assert found.via == "parent"
    assert found.entry.id == "T1059"
    assert found.entry.name == "Command and Scripting Interpreter"


def test_the_exact_id_wins_over_its_parent(tmp_path):
    found = mitre.lookup("T1110.001", path=_write(tmp_path, _extract()))
    assert found is not None and found.via == "exact" and found.entry.id == "T1110.001"


@pytest.mark.parametrize(
    "technique_id",
    [
        "T9999",  # not in the reference
        "T9999.001",  # neither it nor its parent is
        "",
        "   ",
        "T1110.00",  # fails the id pattern
        "T1110.001.002",
        "T1110.abc",  # must not reach T1110 through a split on the dot
        "T111",
        "X1110",
        "1110",
        "T1110 T1059",
        "T1110;",
    ],
)
def test_unknown_or_malformed_ids_answer_none(tmp_path, technique_id):
    assert mitre.lookup(technique_id, path=_write(tmp_path, _extract())) is None


def test_lookup_of_a_non_string_is_none_not_an_error(tmp_path):
    path = _write(tmp_path, _extract())
    for value in (None, 1110, ["T1110"], b"T1110"):
        assert mitre.lookup(value, path=path) is None  # type: ignore[arg-type]


def test_lookup_folds_case_and_trims_like_the_category_tiers(tmp_path):
    path = _write(tmp_path, _extract())
    found = mitre.lookup("  t1110.001 ", path=path)
    assert found is not None and found.entry.id == "T1110.001"


def test_version_is_the_headers(tmp_path):
    assert mitre.version(path=_write(tmp_path, _extract())) == "9.9"


# --- no usable reference: never an error ----------------------------------------------------------


def test_a_missing_file_means_no_reference(tmp_path):
    missing = tmp_path / "nope.json"
    assert mitre.version(path=missing) is None
    assert mitre.lookup("T1110", path=missing) is None


@pytest.mark.parametrize(
    "content",
    [
        "",
        "not json at all",
        "{",
        "[]",
        "null",
        '"text"',
        "{}",
        '{"header": {}, "techniques": {}}',
        '{"header": "x", "techniques": {}}',
        '{"techniques": {}}',
    ],
)
def test_a_damaged_file_means_no_reference(tmp_path, content):
    path = _write(tmp_path, content)
    assert mitre.version(path=path) is None
    assert mitre.lookup("T1110", path=path) is None


def _bad_extracts():
    good = _extract()
    cases = {}
    cases["wrong domain"] = _extract(domain="mobile-attack")
    cases["no version"] = _extract(version="")
    cases["version not a string"] = _extract(version=20.1)
    cases["techniques is a list"] = {"header": good["header"], "techniques": []}
    cases["entry not an object"] = _extract({"T1110": "x"})
    cases["id key malformed"] = _extract({"t1110": _entry("A", "d")})
    cases["id key with junk"] = _extract({"T1110.x": _entry("A", "d")})
    cases["no name"] = _extract({"T1110": _entry("", "d")})
    cases["name not a string"] = _extract({"T1110": {**_entry("A", "d"), "name": 3}})
    cases["tactics not a list"] = _extract({"T1110": {**_entry("A", "d"), "tactics": "x"}})
    cases["tactic not a string"] = _extract({"T1110": {**_entry("A", "d"), "tactics": [1]}})
    cases["bad status"] = _extract({"T1110": _entry("A", "d", status="retired")})
    cases["description not a string"] = _extract(
        {"T1110": {**_entry("A", "d"), "description": None}}
    )
    cases["parent of a top-level technique"] = _extract({"T1110": _entry("A", "d", parent="T1059")})
    cases["parent not the id before the dot"] = _extract(
        {"T1110.001": _entry("A", "d", parent="T1059")}
    )
    cases["sub-technique without parent"] = _extract({"T1110.001": _entry("A", "d", parent=None)})
    for key in ("name", "tactics", "parent", "status", "description"):
        entry = _entry("A", "d")
        del entry[key]
        cases[f"entry missing {key}"] = _extract({"T1110": entry})
    return cases


@pytest.mark.parametrize("case", sorted(_bad_extracts()))
def test_a_file_with_a_wrong_header_or_shape_means_no_reference(tmp_path, case):
    path = _write(tmp_path, _bad_extracts()[case])
    assert mitre.version(path=path) is None
    assert mitre.lookup("T1110", path=path) is None


def test_a_non_utf8_file_means_no_reference(tmp_path):
    path = tmp_path / "e.json"
    path.write_bytes(b"\xff\xfe\x00{")
    assert mitre.version(path=path) is None
    assert mitre.lookup("T1110", path=path) is None


def test_a_directory_in_place_of_the_file_means_no_reference(tmp_path):
    assert mitre.version(path=tmp_path) is None
    assert mitre.lookup("T1110", path=tmp_path) is None


def test_the_default_path_is_mitre_file_read_at_call_time(tmp_path, monkeypatch):
    path = _write(tmp_path, _extract(version="7.7"))
    monkeypatch.setattr(mitre, "MITRE_FILE", path)
    assert mitre.version() == "7.7"
    found = mitre.lookup("T1110")
    assert found is not None and found.entry.name == "Brute Force"
    monkeypatch.setattr(mitre, "MITRE_FILE", tmp_path / "gone.json")
    assert mitre.version() is None and mitre.lookup("T1110") is None


# --- loaded once per process ------------------------------------------------------------------------


def test_the_file_is_read_once_per_process_until_reset_cache(tmp_path):
    path = _write(tmp_path, _extract(version="1.0"))
    assert mitre.version(path=path) == "1.0"
    _write(tmp_path, _extract(version="2.0"))  # the file changes under a running process
    assert mitre.version(path=path) == "1.0"
    assert mitre.lookup("T1110", path=path) is not None
    mitre.reset_cache()
    assert mitre.version(path=path) == "2.0"


def test_a_failed_load_is_not_retried_on_every_call_either(tmp_path):
    path = _write(tmp_path, "{")
    assert mitre.version(path=path) is None
    _write(tmp_path, _extract())
    assert mitre.version(path=path) is None  # still the first answer
    mitre.reset_cache()
    assert mitre.version(path=path) == "9.9"


def test_two_paths_do_not_share_a_cache_entry(tmp_path):
    a = _write(tmp_path, _extract(version="1.0"), "a.json")
    b = _write(tmp_path, _extract(version="2.0"), "b.json")
    assert mitre.version(path=a) == "1.0"
    assert mitre.version(path=b) == "2.0"


# --- the committed extract (ATT&CK Enterprise 20.1) ------------------------------------------------


@pytest.fixture(scope="module")
def committed() -> dict:
    return json.loads(COMMITTED.read_text(encoding="utf-8"))


def _category_ids() -> set[str]:
    return (
        set(category.WINDOWS_TECHNIQUE_TO_CATEGORY)
        | set(category.TECHNIQUE_TO_CATEGORY)
        | set(category.EXTENDED_TECHNIQUE_TO_CATEGORY)
    )


def test_committed_header(committed):
    header = committed["header"]
    assert header["domain"] == "enterprise-attack"
    assert header["version"] == "20.1"
    assert header["modified"].startswith("2026-11-05")
    assert header["source_sha256"] == BUNDLE_SHA256
    assert header["source_url"] == BUNDLE_URL
    assert header["extracted_by"] == "scripts/mitre_extract.py"
    assert header["copyright"].startswith("Copyright") and "MITRE" in header["copyright"]
    assert "copyright designation" in header["terms"] and "royalty-free" in header["terms"]
    assert mitre.version() == "20.1"


def test_committed_extract_is_small_stable_json(committed):
    raw = COMMITTED.read_bytes()
    assert 100_000 < len(raw) < 1_000_000
    text = raw.decode("utf-8")
    assert text == json.dumps(committed, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    ids = list(committed["techniques"])
    assert ids == sorted(ids)
    assert "revoked-by" not in text and "(Citation:" not in text and "<code>" not in text


def test_committed_extract_holds_706_live_techniques_of_867(committed):
    statuses = [t["status"] for t in committed["techniques"].values()]
    assert len(statuses) == 867
    assert statuses.count("live") == 706
    assert statuses.count("revoked") + statuses.count("deprecated") == 867 - 706
    live_subs = [
        i for i, t in committed["techniques"].items() if t["status"] == "live" and t["parent"]
    ]
    assert len(live_subs) == 479


def test_committed_entries_are_well_formed(committed):
    techniques = committed["techniques"]
    for tid, entry in techniques.items():
        assert entry["name"], tid
        assert entry["tactics"], tid
        assert entry["status"] in {"live", "revoked", "deprecated"}
        assert len(entry["description"]) <= mitre.DESCRIPTION_MAX_CHARS, tid
        assert entry["parent"] == (tid.split(".")[0] if "." in tid else None), tid
        if entry["parent"]:
            assert entry["parent"] in techniques, tid
        # MITRE's deprecation notice (a word about status, naming a replacement) is not carried.
        assert "has been deprecated" not in entry["description"], tid
        assert "Please use" not in entry["description"], tid


def test_the_committed_extract_is_what_the_tool_makes_of_the_official_bundle(committed):
    if not BUNDLE.is_file():
        pytest.skip("the official bundle is not on this machine")
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import mitre_extract

    raw = BUNDLE.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BUNDLE_SHA256
    rebuilt = mitre_extract.build_extract(
        json.loads(raw), source_sha256=BUNDLE_SHA256, source_url=BUNDLE_URL
    )
    assert rebuilt == committed


def test_every_technique_id_of_the_category_tables_resolves_exactly_with_mitres_text():
    """G1a: the 372 ids of `ingest/category.py` (the vocabulary of the product's technique map)."""
    ids = _category_ids()
    assert len(ids) == 372
    statuses = {"live": 0, "revoked": 0, "deprecated": 0}
    for technique_id in sorted(ids):
        found = mitre.lookup(technique_id)
        assert found is not None, f"{technique_id} is in category.py but not in the MITRE reference"
        assert found.via == "exact", technique_id
        assert found.entry.id == technique_id
        assert found.entry.name, technique_id
        assert found.entry.tactics, technique_id
        assert found.entry.description.strip(), technique_id
        statuses[found.entry.status] += 1
    assert statuses == {"live": 229, "revoked": 132, "deprecated": 11}


def test_committed_extract_answers_a_sub_technique_a_rule_may_carry():
    found = mitre.lookup("T1110.001")
    assert found is not None and found.via == "exact"
    assert found.entry.parent == "T1110" and found.entry.name == "Password Guessing"
    # A made-up sub-technique under a real parent is found through the parent.
    found = mitre.lookup("T1110.999")
    assert found is not None and found.via == "parent" and found.entry.id == "T1110"
    assert mitre.lookup("T9999") is None


def test_a_replaced_id_is_described_with_its_own_data_and_names_no_replacement():
    # T1073 (DLL Side-Loading, revoked) was replaced by T1574.001; the bundle says so, the extract
    # does not (Owner, 17/11).
    found = mitre.lookup("T1073")
    assert found is not None and found.via == "exact" and found.entry.id == "T1073"
    blob = " ".join(
        [found.entry.name, found.entry.description, found.entry.status, *found.entry.tactics]
    )
    assert "T1574" not in blob
    assert "Hijack Execution Flow" not in blob
    assert "revoked-by" not in COMMITTED.read_text(encoding="utf-8")
