"""`scripts/mitre_extract.py` — turns the official ATT&CK Enterprise STIX bundle into the small
committed extract `kb/mitre/enterprise-attack.json` (DEC-223 T1, spec §4.1 and §4.2).

The tests build a small hand-made bundle shaped like the real one (the 55 MB bundle is never
committed, anti-goal A5) and check: the fields of each kind of technique, the clean-up of the
description (citations, Markdown links, HTML tags, white space, the 600-character cut), the
Owner's rule of 17/11 that a revoked or deprecated id keeps its own text and nothing about a
replacement is stored, a refusal of anything that is not an Enterprise bundle, byte-identical
output, and that the tool opens no socket (A1).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import socket
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))  # the pattern test_dec_overlaps.py uses
import mitre_extract

SHA = "a" * 64
URL = "https://example.invalid/attack/enterprise-attack-9.9.json"
MARKING_ID = "marking-definition--fa42a846-8d90-4e51-bc29-71d5b4802168"
COPYRIGHT = "Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered."

LONG_WORDS = " ".join(f"word{i:03d}" for i in range(200))  # 1 799 characters, words of 7


def _technique(
    ext_id: str,
    name: str,
    description: str,
    *,
    tactics: tuple[str, ...] = ("credential-access",),
    platforms: tuple[str, ...] = ("Windows",),
    subtechnique: bool = False,
    revoked: bool | None = False,
    deprecated: bool | None = False,
    domains: tuple[str, ...] = ("enterprise-attack",),
) -> dict:
    obj: dict = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{ext_id.replace('.', '-').lower()}",
        "name": name,
        "description": description,
        "external_references": [
            {"source_name": "other source", "external_id": "NOT-A-TECHNIQUE"},
            {
                "source_name": "mitre-attack",
                "external_id": ext_id,
                "url": "https://example.invalid",
            },
        ],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": t} for t in tactics
        ],
        "x_mitre_platforms": list(platforms),
        "x_mitre_is_subtechnique": subtechnique,
        "x_mitre_domains": list(domains),
    }
    if revoked is not None:
        obj["revoked"] = revoked
    if deprecated is not None:
        obj["x_mitre_deprecated"] = deprecated
    return obj


def hand_bundle() -> dict:
    live = _technique(
        "T1110",
        "Brute Force",
        "Adversaries may use brute force techniques to gain access to accounts.(Citation: Dell"
        " Password Guessing) See [Valid Accounts](https://attack.mitre.org/techniques/T1078) and"
        " run <code>net user</code> for <b>more</b>.\n\n"
        "A second paragraph that is not kept.(Citation: Second)",
        tactics=("credential-access",),
        platforms=("Windows", "Linux"),
    )
    sub = _technique(
        "T1110.001",
        "Password Guessing",
        "Adversaries with no prior knowledge of legitimate credentials may guess passwords.",
        subtechnique=True,
    )
    deprecated = _technique(
        "T1064",
        "Scripting",
        "**This technique has been deprecated. Please use [Command and Scripting Interpreter]"
        "(https://attack.mitre.org/techniques/T1059) where appropriate.**\n\n"
        "Adversaries may use scripts to aid in operations.(Citation: Scripts)\n\nMore.",
        tactics=("stealth", "execution"),
        revoked=None,
        deprecated=True,
    )
    deprecated_plain = _technique(
        "T1053.004",
        "Launchd",
        "This technique is deprecated due to the inaccurate usage. The report cited did not give"
        " detail. \n\nAdversaries may abuse the <code>Launchd</code> daemon.",
        tactics=("execution", "persistence"),
        subtechnique=True,
        revoked=None,
        deprecated=True,
    )
    revoked_with = _technique(
        "T1073",
        "DLL Side-Loading",
        "Programs may specify DLLs that are loaded at runtime. This old technique was replaced"
        " in later versions.",
        tactics=("persistence",),
        revoked=True,
        deprecated=None,
    )
    revoked_without = _technique(
        "T1099",
        "Timestomp",
        "Adversaries may modify file times.",
        tactics=("stealth",),
        revoked=True,
        deprecated=None,
    )
    long_one = _technique(
        "T1590",
        "Gather Victim Network Information",
        f"{LONG_WORDS}\n\nSecond paragraph.",
        tactics=("reconnaissance",),
    )
    mobile = _technique(
        "T1404", "Exploit OS Vulnerability", "Mobile only.", domains=("mobile-attack",)
    )
    return {
        "type": "bundle",
        "id": "bundle--1",
        "objects": [
            {"type": "identity", "id": "identity--1", "name": "MITRE"},
            {
                "type": "marking-definition",
                "id": MARKING_ID,
                "definition_type": "statement",
                "definition": {"statement": COPYRIGHT},
            },
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--1",
                "name": "Enterprise ATT&CK",
                "x_mitre_version": "9.9",
                "modified": "2026-11-05T15:11:27.678Z",
                "object_marking_refs": [MARKING_ID],
            },
            live,
            sub,
            deprecated,
            deprecated_plain,
            revoked_with,
            revoked_without,
            long_one,
            mobile,
            {"type": "malware", "id": "malware--1", "name": "SomeMalware", "description": "x"},
            # The link from the old id to what replaced it: the tool does not read it, so the
            # extract has no trace of it (Owner, 17/11).
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "revoked-by",
                "source_ref": revoked_with["id"],
                "target_ref": sub["id"],
            },
        ],
    }


@pytest.fixture
def extract() -> dict:
    return mitre_extract.build_extract(hand_bundle(), source_sha256=SHA, source_url=URL)


# --- the header and the shape ----------------------------------------------------------------


def test_header_is_the_bundles_own_plus_the_given_provenance(extract):
    header = extract["header"]
    assert header["domain"] == "enterprise-attack"
    assert header["version"] == "9.9"
    assert header["modified"] == "2026-11-05T15:11:27.678Z"
    assert header["source_sha256"] == SHA
    assert header["source_url"] == URL
    assert header["copyright"] == COPYRIGHT
    assert header["extracted_by"] == "scripts/mitre_extract.py"
    assert "royalty-free" in header["terms"]
    assert "copyright designation" in header["terms"]
    assert "attack.mitre.org" in header["terms"]
    # The attribution line MITRE's terms page asks for, verbatim (Ruling M4).
    assert header["terms"].endswith(
        "\u00a9 2026 The MITRE Corporation. This work is reproduced and distributed with the"
        " permission of The MITRE Corporation."
    )
    assert set(header) == {
        "domain",
        "version",
        "modified",
        "source_sha256",
        "source_url",
        "copyright",
        "terms",
        "extracted_by",
    }


def test_techniques_are_keyed_by_the_mitre_attack_external_id_and_carry_only_the_listed_keys(
    extract,
):
    techniques = extract["techniques"]
    # The mobile-only technique, the malware and the relationship are not techniques of this domain.
    assert sorted(techniques) == [
        "T1053.004",
        "T1064",
        "T1073",
        "T1099",
        "T1110",
        "T1110.001",
        "T1590",
    ]
    for entry in techniques.values():
        assert set(entry) == {"name", "tactics", "parent", "status", "platforms", "description"}


def test_live_technique_fields_and_description_cleaning(extract):
    entry = extract["techniques"]["T1110"]
    assert entry["name"] == "Brute Force"
    assert entry["tactics"] == ["credential-access"]
    assert entry["parent"] is None
    assert entry["status"] == "live"
    assert entry["platforms"] == ["Windows", "Linux"]
    # The first paragraph only; the citation is gone, the link keeps its text, the tags go.
    assert entry["description"] == (
        "Adversaries may use brute force techniques to gain access to accounts."
        " See Valid Accounts and run net user for more."
    )


def test_sub_technique_has_its_parent_the_id_before_the_dot(extract):
    entry = extract["techniques"]["T1110.001"]
    assert entry["parent"] == "T1110"
    assert entry["status"] == "live"
    assert entry["description"].startswith("Adversaries with no prior knowledge")


def test_tactics_keep_attacks_own_names_and_order(extract):
    assert extract["techniques"]["T1064"]["tactics"] == ["stealth", "execution"]
    assert extract["techniques"]["T1053.004"]["tactics"] == ["execution", "persistence"]


@pytest.mark.parametrize(
    ("ext_id", "status"),
    [
        ("T1110", "live"),
        ("T1110.001", "live"),
        ("T1064", "deprecated"),
        ("T1053.004", "deprecated"),
        ("T1073", "revoked"),
        ("T1099", "revoked"),
    ],
)
def test_status(extract, ext_id, status):
    assert extract["techniques"][ext_id]["status"] == status


def test_revoked_and_deprecated_keep_their_own_name_tactics_and_description(extract):
    revoked = extract["techniques"]["T1073"]
    assert revoked["name"] == "DLL Side-Loading"
    assert revoked["tactics"] == ["persistence"]
    assert revoked["description"].startswith("Programs may specify DLLs")
    deprecated = extract["techniques"]["T1064"]
    assert deprecated["name"] == "Scripting"
    assert deprecated["tactics"] == ["stealth", "execution"]


def test_a_replacement_is_neither_stored_nor_named(extract):
    # The `revoked-by` relationship and the deprecation notice naming a replacement are not
    # carried: the entry has exactly its own data (Owner, 17/11).
    text = json.dumps(extract, ensure_ascii=False)
    assert "revoked-by" not in text
    assert "relationship" not in text
    assert "Command and Scripting Interpreter" not in text
    assert "T1059" not in text
    assert "target_ref" not in text
    revoked = json.dumps(extract["techniques"]["T1073"])
    assert "T1110" not in revoked
    assert "Password Guessing" not in revoked


def test_the_deprecation_notice_paragraph_is_not_the_description(extract):
    # MITRE puts "This technique has been deprecated. Please use X" as the first paragraph of a
    # deprecated technique: a word about its status and its replacement, so it is skipped and the
    # description is MITRE's own next paragraph, verbatim after the clean-up.
    assert extract["techniques"]["T1064"]["description"] == (
        "Adversaries may use scripts to aid in operations."
    )
    assert extract["techniques"]["T1053.004"]["description"] == (
        "Adversaries may abuse the Launchd daemon."
    )
    for entry in extract["techniques"].values():
        assert "deprecated" not in entry["description"].lower()
        assert "Please use" not in entry["description"]


def test_a_description_over_600_characters_is_cut_on_a_word_boundary(extract):
    description = extract["techniques"]["T1590"]["description"]
    assert len(description) <= mitre_extract.DESCRIPTION_MAX_CHARS == 600
    assert description.endswith(" …")
    kept = description[: -len(" …")]
    assert LONG_WORDS.startswith(kept)
    assert LONG_WORDS[len(kept)] == " "  # the cut is between two words, not inside one
    assert "Second paragraph" not in description
    # A paragraph that fits is not touched and gets no ellipsis.
    assert not extract["techniques"]["T1099"]["description"].endswith("…")


# --- clean_description -----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Plain text.", "Plain text."),
        ("  Leading and trailing space.  \n", "Leading and trailing space."),
        ("First.\n\nSecond.", "First."),
        ("First line\nsame paragraph.\n\nSecond.", "First line same paragraph."),
        ("Cited.(Citation: A B 2017)(Citation: C) More.", "Cited. More."),
        ("Cited (Citation: Startup Items). Next.", "Cited. Next."),
        (
            "See [Process Injection](https://attack.mitre.org/techniques/T1055) now.",
            "See Process Injection now.",
        ),
        ("Run <code>whoami /all</code> and <b>x</b>.", "Run whoami /all and x."),
        ("One<br>two<br/>three.", "One two three."),
        ("Registry key <code>HKLM\\Software\\X</code>.", "Registry key HKLM\\Software\\X."),
        ("  Many   spaces\tand\ttabs  ", "Many spaces and tabs"),
        # Placeholders MITRE writes between angle brackets are MITRE's text, not HTML tags.
        ("Run as <DOMAIN>\\<username> in <code>x</code>.", "Run as <DOMAIN>\\<username> in x."),
        # Backticks are MITRE's own Markdown and are kept.
        ("Use `mkdir -p` here.", "Use `mkdir -p` here."),
        # A deprecation notice naming a replacement is skipped, bold or plain.
        (
            "**This technique has been deprecated. Please use [X](https://a.b/T1) where appropriate.**\n\nReal text.",
            "Real text.",
        ),
        ("**This technique has been deprecated and should no longer be used.**\n\nReal.", "Real."),
        ("This technique is deprecated due to the inaccurate usage. Why.\n\nReal.", "Real."),
        # The notice pasted by mistake into the middle of MITRE's own sentence (T1153 in 20.1) goes.
        (
            "Run <code>x</code> or <code>.**This technique has been deprecated and should no longer be used.** /path</code> now.",
            "Run x or . /path now.",
        ),
        # A paragraph that leads in to a list is completed by the list's items (m1): the markers
        # become plain separators, MITRE's words stay, and nothing after the list is appended.
        (
            "Ports such as\n\n* TCP:80 (HTTP)\n* TCP:443 (HTTPS)\n\nThey may use more.",
            "Ports such as TCP:80 (HTTP); TCP:443 (HTTPS)",
        ),
        (
            "Include:(Citation: X)\n\n* One\n- Two.\n1. Three\n\nAfter.",
            "Include: One; Two. Three",
        ),
        (
            "Items:\n\n* <code>/var/log/x</code>: Logs\n* [Link](https://a.b/T1) text (Citation: Y)\n",
            "Items: /var/log/x: Logs; Link text",
        ),
        # No list after it: the next paragraphs follow until one ends a sentence.
        (
            "Lead in without a stop\n\nNext sentence here.\n\nThird.",
            "Lead in without a stop Next sentence here.",
        ),
        (
            "Ends with a colon:\n\nA plain paragraph, that ends no sentence\n\nThen a full one.\n\nMore.",
            "Ends with a colon: A plain paragraph, that ends no sentence Then a full one.",
        ),
        # A paragraph that ends a sentence is complete, whatever follows it.
        ("A complete sentence.\n\n* not appended\n* nor this", "A complete sentence."),
        ("A sentence (in brackets.)\n\nNext.", "A sentence (in brackets.)"),
        ('Said "stop."\n\nNext.', 'Said "stop."'),
        ("Is it?\n\nNext.", "Is it?"),
        # A lead-in with nothing after it is kept as it is.
        ("Such as:", "Such as:"),
        # The notice in other tenses is skipped too (m2).
        ("This technique was deprecated.\n\nReal.", "Real."),
        # Only the notice: nothing of MITRE's own to show.
        ("**This technique has been deprecated and should no longer be used.**", ""),
        # A live technique that merely talks about a deprecated API keeps its text.
        (
            "Although this API is deprecated, it still works.",
            "Although this API is deprecated, it still works.",
        ),
        ("", ""),
    ],
)
def test_clean_description(raw, expected):
    assert mitre_extract.clean_description(raw) == expected


def test_clean_description_cut_boundaries():
    limit = mitre_extract.DESCRIPTION_MAX_CHARS
    exactly = "a" * (limit - 1) + "b"
    assert mitre_extract.clean_description(exactly) == exactly  # 600 characters: not cut
    over = "x" * limit + " tail"
    cut = mitre_extract.clean_description(over)
    assert len(cut) <= limit
    assert cut.endswith(" …")
    # No space to cut at before the limit: the word is cut at the limit, never longer.
    one_word = "y" * (limit + 50)
    cut = mitre_extract.clean_description(one_word)
    assert len(cut) <= limit and cut.endswith(" …")


def test_a_list_after_a_lead_in_is_cut_at_the_cap():
    items = "\n".join(f"* item number {i:03d}" for i in range(100))
    out = mitre_extract.clean_description("Such as:\n\n" + items)
    assert out.startswith("Such as: item number 000; item number 001; item number 002")
    assert len(out) <= mitre_extract.DESCRIPTION_MAX_CHARS and out.endswith(" \u2026")


def test_a_lead_in_is_completed_in_a_built_extract_and_a_deprecated_one_keeps_no_notice():
    bundle = hand_bundle()
    bundle["objects"].append(
        _technique(
            "T1043",
            "Commonly Used Port",
            "**This technique has been deprecated. Please use [Non-Standard Port]"
            "(https://attack.mitre.org/techniques/T1571) where appropriate.**\n\n"
            "Adversaries may use commonly open ports such as\n\n* TCP:80 (HTTP)\n* TCP:443 (HTTPS)"
            "\n\nThey may use the protocol associated with the port.",
            tactics=("command-and-control",),
            revoked=None,
            deprecated=True,
        )
    )
    built = mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)
    assert built["techniques"]["T1043"]["description"] == (
        "Adversaries may use commonly open ports such as TCP:80 (HTTP); TCP:443 (HTTPS)"
    )


def test_a_deprecated_entry_whose_text_would_still_say_deprecated_is_refused(tmp_path, capsys):
    # The tool's notice rule knows MITRE's notice sentences; a text in other words that still
    # says "deprecated" would put a word about status in front of the model, so nothing is written.
    bundle = hand_bundle()
    bundle["objects"] += [
        _technique(
            "T1043",
            "Commonly Used Port",
            "Deprecated in favour of another technique.\n\nMore.",
            revoked=None,
            deprecated=True,
        ),
        _technique(
            "T1044",
            "File System Permissions Weakness",
            "Adversaries may overwrite a binary. It was Deprecated in 2019.",
            revoked=None,
            deprecated=True,
        ),
        # Live and revoked entries may talk about a deprecated API: that is their content.
        _technique("T1045", "Software Packing", "Although this API is deprecated, it works."),
        _technique(
            "T1046",
            "Some Old One",
            "The API is deprecated but works.",
            revoked=True,
            deprecated=None,
        ),
    ]
    with pytest.raises(mitre_extract.DeprecationWordInDescription) as refused:
        mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)
    assert "T1043" in str(refused.value) and "T1044" in str(refused.value)
    assert "T1045" not in str(refused.value) and "T1046" not in str(refused.value)
    assert "2 deprecated" in str(refused.value)
    out = tmp_path / "e.json"
    path = _write_bundle(tmp_path / "b.json", bundle)
    assert mitre_extract.main([str(path), "--out", str(out)]) == 2
    assert not out.exists()
    err = capsys.readouterr().err
    assert "2 deprecated" in err and "T1043" in err and "T1044" in err


def test_an_external_id_ending_in_a_newline_is_not_a_technique_id():
    bundle = hand_bundle()
    bundle["objects"].append(_technique("T1999\n", "Newline", "Text."))
    built = mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)
    assert not any("T1999" in key for key in built["techniques"])


# --- refusing a file that is not an ATT&CK Enterprise bundle -----------------------------------


@pytest.mark.parametrize(
    "bundle",
    [
        {},
        {"type": "bundle", "objects": []},
        {"type": "bundle", "objects": "no"},
        {"type": "not-a-bundle", "objects": []},
        [],
        "text",
    ],
)
def test_build_extract_refuses_what_is_not_a_bundle(bundle):
    with pytest.raises(mitre_extract.NotAnEnterpriseBundle):
        mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)


def test_build_extract_refuses_a_bundle_without_its_collection_object():
    bundle = hand_bundle()
    bundle["objects"] = [o for o in bundle["objects"] if o["type"] != "x-mitre-collection"]
    with pytest.raises(mitre_extract.NotAnEnterpriseBundle):
        mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)


def test_build_extract_refuses_a_mobile_bundle():
    bundle = hand_bundle()
    for obj in bundle["objects"]:
        if obj["type"] == "attack-pattern":
            obj["x_mitre_domains"] = ["mobile-attack"]
    with pytest.raises(mitre_extract.NotAnEnterpriseBundle):
        mitre_extract.build_extract(bundle, source_sha256=SHA, source_url=URL)


# --- main: files, exit codes, determinism -----------------------------------------------------


def _write_bundle(path: pathlib.Path, bundle: dict | None = None) -> pathlib.Path:
    path.write_text(json.dumps(bundle or hand_bundle()), encoding="utf-8")
    return path


def test_main_writes_the_extract_and_returns_0(tmp_path, capsys):
    bundle = _write_bundle(tmp_path / "enterprise-attack-9.9.json")
    out = tmp_path / "out" / "extract.json"
    assert mitre_extract.main([str(bundle), "--out", str(out)]) == 0
    written = json.loads(out.read_text(encoding="utf-8"))
    assert written["header"]["version"] == "9.9"
    assert written["header"]["source_sha256"] == hashlib.sha256(bundle.read_bytes()).hexdigest()
    assert written["header"]["source_url"].endswith("/enterprise-attack/enterprise-attack-9.9.json")
    assert written["header"]["source_url"].startswith("https://")
    assert "7 techniques" in capsys.readouterr().out


def test_main_source_url_can_be_given(tmp_path):
    bundle = _write_bundle(tmp_path / "b.json")
    out = tmp_path / "e.json"
    assert mitre_extract.main([str(bundle), "--out", str(out), "--source-url", URL]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["header"]["source_url"] == URL


def test_output_is_stable_json_with_sorted_keys_unescaped_text_and_a_trailing_newline(tmp_path):
    bundle = hand_bundle()
    bundle["objects"][3]["name"] = "Brute Force — Apple’s"  # a non-ASCII name stays as it is
    path = _write_bundle(tmp_path / "b.json", bundle)
    out = tmp_path / "e.json"
    assert mitre_extract.main([str(path), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert "Brute Force — Apple’s" in text
    assert "\\u" not in text
    assert text == json.dumps(json.loads(text), indent=1, sort_keys=True, ensure_ascii=False) + "\n"
    ids = list(json.loads(text)["techniques"])
    assert ids == sorted(ids)


def test_two_runs_give_the_same_bytes_whatever_the_object_order(tmp_path):
    first = _write_bundle(tmp_path / "a.json")
    shuffled = hand_bundle()
    shuffled["objects"].reverse()
    second = _write_bundle(tmp_path / "b.json", shuffled)
    out_a, out_b, out_c = (tmp_path / n for n in ("1.json", "2.json", "3.json"))
    assert mitre_extract.main([str(first), "--out", str(out_a), "--source-url", URL]) == 0
    assert mitre_extract.main([str(first), "--out", str(out_b), "--source-url", URL]) == 0
    assert mitre_extract.main([str(second), "--out", str(out_c), "--source-url", URL]) == 0
    assert out_a.read_bytes() == out_b.read_bytes()
    # Same techniques, whatever order the bundle lists them (the sha differs: another file).
    assert (
        json.loads(out_a.read_text())["techniques"] == json.loads(out_c.read_text())["techniques"]
    )


def test_main_refuses_a_file_that_is_not_an_attack_bundle_with_2_and_writes_nothing(
    tmp_path, capsys
):
    out = tmp_path / "e.json"
    junk = tmp_path / "junk.json"
    junk.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    assert mitre_extract.main([str(junk), "--out", str(out)]) == 2
    assert not out.exists()
    assert "not an ATT&CK Enterprise bundle" in capsys.readouterr().err
    not_json = tmp_path / "x.json"
    not_json.write_text("<html>", encoding="utf-8")
    assert mitre_extract.main([str(not_json), "--out", str(out)]) == 2
    assert mitre_extract.main([str(tmp_path / "missing.json"), "--out", str(out)]) == 2
    assert not out.exists()


def test_main_usage_errors_return_2(capsys):
    assert mitre_extract.main([]) == 2
    assert mitre_extract.main(["a.json", "--no-such-flag"]) == 2


def test_main_never_takes_a_url(tmp_path, capsys):
    out = tmp_path / "e.json"
    assert mitre_extract.main(["https://example.invalid/b.json", "--out", str(out)]) == 2
    assert not out.exists()


def test_the_tool_opens_no_socket(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise AssertionError("the tool must not touch the network (A1)")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    bundle = _write_bundle(tmp_path / "b.json")
    assert mitre_extract.main([str(bundle), "--out", str(tmp_path / "e.json")]) == 0
