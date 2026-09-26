"""The containers must see every repository path the web code reads at runtime (DEC-135).

Inside the compose services the repository is mirrored under `/srv` (docker-compose.yml's own
comment), so a module computing `REPO_ROOT = Path(__file__).resolve().parents[3]` gets `/srv`.
The image copies only `backend/app` and `kb` (backend/Dockerfile); anything else the code reads
must be a bind mount. `tier1/labels.py` reads `eval/gold_candidates.csv`, and `./eval` was not
mounted: the blind labelling page would have found no candidates in the container on 28/09 while
every native test passed, because natively `REPO_ROOT` is the checkout. Found by reading the
compose file on 26/09, not by the suite, hence this test.
"""

from pathlib import Path, PurePosixPath

import yaml
from app.kb import lookup
from app.tier1 import labels

REPO_ROOT = Path(__file__).resolve().parents[2]
CONTAINER_ROOT = PurePosixPath("/srv")


def _compose() -> dict:
    return yaml.safe_load((REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def _mounts(service: str) -> dict[str, tuple[str, str]]:
    """container path -> (host path, mode) for one service's bind mounts."""
    mounts = {}
    for volume in _compose()["services"][service]["volumes"]:
        host, container, *rest = volume.split(":")
        mounts[container] = (host, rest[0] if rest else "rw")
    return mounts


def _top_directory(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).parts[0]


def _assert_mounted_read_only(service: str, top: str) -> None:
    mounts = _mounts(service)
    container = str(CONTAINER_ROOT / top)
    assert container in mounts, (
        f"{service}: the code reads {top}/ relative to the repository root, which is {CONTAINER_ROOT} "
        f"in the container, but {container} is not mounted (mounted: {sorted(mounts)})"
    )
    assert mounts[container] == (f"./{top}", "ro"), mounts[container]


def test_the_labelling_candidates_file_is_mounted_read_only_in_the_app():
    top = _top_directory(labels.CANDIDATES_PATH, labels.REPO_ROOT)
    assert top == "eval"
    _assert_mounted_read_only("app", top)


def test_the_decision_tables_are_mounted_read_only_in_the_app():
    top = _top_directory(lookup.KB_ROOT, REPO_ROOT)
    assert top == "kb"
    _assert_mounted_read_only("app", top)


def test_the_worker_shares_the_app_mounts():
    services = _compose()["services"]
    assert services["worker"]["volumes"] == services["app"]["volumes"]
