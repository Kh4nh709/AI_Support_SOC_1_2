"""SR-T1 — the README's section "Phản hồi SOAR": what the feature is, the nine settings, the port n8n must post to, three `curl`
examples for `POST /webhook/soar-notices` and how to run the stand-in n8n.

The examples are held to the code: each body in them is parsed by the route's own reader (`soar/review_notice.parse`), so an
example that n8n's builder copies is one the web accepts. Pure: reads `README.md` and nothing else.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest
from app.soar import review_notice

README = pathlib.Path(__file__).resolve().parents[2] / "README.md"

KEYS = (
    "SOAR_NOTICE_API_KEY",
    "SOAR_NOTICE_IP_ALLOWLIST",
    "N8N_APPROVAL_URL",
    "N8N_APPROVAL_SECRET",
    "N8N_APPROVAL_TIMEOUT_SECONDS",
    "SOAR_ROLES_KEEP",
    "SOAR_ROLES_UNDO",
    "SOAR_ROLES_FP",
    "SOAR_AD_HOSTS",
)


def _section() -> str:
    text = README.read_text(encoding="utf-8")
    assert "\n## Phản hồi SOAR\n" in text, "README.md has no section 'Phản hồi SOAR'"
    return text.split("\n## Phản hồi SOAR\n", 1)[1].split("\n## ", 1)[0]


def _curls() -> list[tuple[str, dict]]:
    """Each fenced `curl` of the section: its text and the JSON body after `-d`."""
    blocks = re.findall(r"```bash\n(curl .*?)```", _section(), re.DOTALL)
    found = []
    for block in blocks:
        match = re.search(r"-d '(\{.*\})'", block, re.DOTALL)
        assert match, f"a curl with no -d body:\n{block}"
        found.append((block, json.loads(match.group(1))))
    return found


def test_the_section_is_in_vietnamese_and_says_what_it_is():
    text = _section()
    for phrase in ("n8n", "phiếu", "Telegram", "/webhook/soar-notices", "/soar"):
        assert phrase in text, phrase


@pytest.mark.parametrize("key", KEYS)
def test_every_setting_is_named_in_the_section(key):
    assert f"`{key}`" in _section()


def test_it_says_n8n_posts_to_the_apps_own_port_not_the_uis():
    text = _section()
    assert ":8001" in text and ":8000" in text
    assert ":8081" in text  # named, as the port that must NOT be used
    assert re.search(
        r"không.{0,40}:8081|:8081.{0,60}không", text, re.IGNORECASE
    ), "the UI port is not ruled out"


def test_there_are_exactly_three_curl_examples_a_block_ip_a_kill_process_and_a_notice():
    curls = _curls()
    assert len(curls) == 3
    kinds = [(body["kind"], (body.get("action") or {}).get("type")) for _, body in curls]
    assert kinds == [("review", "block_ip"), ("review", "kill_process"), ("notice", None)]


def test_each_curl_posts_to_the_route_with_a_placeholder_key_never_a_real_one():
    for block, _ in _curls():
        assert "/webhook/soar-notices" in block
        assert "-X POST" in block or "--request POST" in block
        assert "Content-Type: application/json" in block
        match = re.search(r"X-API-Key: (\S+?)['\"]?\s", block)
        assert match, block
        assert match.group(1).startswith(
            ("<", "$")
        ), f"the key in the example is not a placeholder: {match.group(1)}"


@pytest.mark.parametrize("index", [0, 1, 2], ids=["block_ip", "kill_process", "notice"])
def test_each_example_body_is_accepted_by_the_webhooks_own_reader(index):
    _, body = _curls()[index]
    notice = review_notice.parse(json.dumps(body).encode())
    assert notice.kind == body["kind"]
    assert notice.id == body["id"]


def test_the_two_review_examples_offer_the_buttons_their_action_allows():
    (_, block_ip), (_, kill), _ = _curls()
    assert [b["decision"] for b in block_ip["buttons"]] == ["keep", "undo"]
    assert [b["decision"] for b in kill["buttons"]] == [
        "keep",
        "fp",
    ]  # a killed process is never undone


def test_it_says_how_to_run_the_stand_in_n8n_and_names_its_four_modes():
    text = _section()
    assert "scripts/mock_n8n_approval.py" in text
    for mode in ("ok", "fail", "conflict", "slow"):
        assert f"`{mode}`" in text, mode
    assert "N8N_APPROVAL_URL=http://127.0.0.1:5678/webhook/soar-approval" in text


def test_the_resend_rule_names_the_three_fields_a_push_cannot_erase():
    """An update replaces every field of the stored ticket, except the record of a decision."""
    text = _section()
    paragraph = next(line for line in text.splitlines() if line.startswith("Gửi lại cùng `id`"))
    for name in ("decided_by", "decided_at", "result"):
        assert f"`{name}`" in paragraph, name
    assert "giữ" in paragraph  # null or absent keeps the stored value


def test_the_api_part_names_the_count_key_the_new_column_and_the_hash_in_q():
    text = _section()
    assert "`latest_received_at`" in text and "`received_at`" in text
    assert "latest_created_at" not in text  # the old key is gone
    assert "#65" in text  # q


def test_the_ad_hosts_wording_says_the_name_is_normalised_in_the_readme_the_runbook_and_the_example():
    runbook = (README.parent / "docs" / "runbook.md").read_text(encoding="utf-8")
    row = next(line for line in runbook.splitlines() if line.startswith("| `SOAR_AD_HOSTS` |"))
    example = next(
        line
        for line in (README.parent / ".env.example").read_text(encoding="utf-8").splitlines()
        if line.startswith("SOAR_AD_HOSTS=")
    )
    readme_row = next(
        line for line in _section().splitlines() if line.startswith("| `SOAR_AD_HOSTS` |")
    )
    for where, text in (("runbook", row), ("example", example), ("README", readme_row)):
        assert "without case" not in text, where
    assert "normalised" in row and "first DNS label" in row
    assert "normalised" in example and "label" in example
    assert "chuẩn hoá" in readme_row and "nhãn DNS đầu" in readme_row


def test_the_section_leaves_the_answers_of_the_route_documented():
    text = _section()
    for code in ("201", "200", "400", "401", "403", "413", "503"):
        assert code in text, code


def test_i2_the_docs_say_what_the_code_does_with_a_blank_approval_url():
    """Absent: the default. Present and empty: off. The loader does exactly this (`test_soar_review_config.py`)."""
    readme = next(
        line for line in _section().splitlines() if line.startswith("| `N8N_APPROVAL_URL` |")
    )
    assert "Không có dòng" in readme and "để trống" in readme and "503" in readme
    runbook = (README.parent / "docs" / "runbook.md").read_text(encoding="utf-8")
    row = next(line for line in runbook.splitlines() if line.startswith("| `N8N_APPROVAL_URL` |"))
    assert "ABSENT" in row and "EMPTY" in row
    example = (README.parent / ".env.example").read_text(encoding="utf-8")
    line = next(line for line in example.splitlines() if line.startswith("N8N_APPROVAL_URL="))
    assert "absent" in line and "EMPTY" in line
