"""Build-efficiency / layer-caching checks (DFA-030 to DFA-034)."""

from __future__ import annotations

import re
from collections.abc import Iterable

from dockerfile_audit.findings import DockerfileDoc, Finding, check_meta

CATEGORY = "efficiency"


@check_meta(id="DFA-030", severity="low", title="apt-get update without install")
def check_apt_update_alone(doc: DockerfileDoc) -> Iterable[Finding]:
    """Flag `apt-get update` that's NOT chained with install in the same RUN.

    The standalone update creates a cached layer with stale package lists; later
    RUNs that install will use those stale lists.
    """
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not value:
            continue
        if "apt-get update" not in value and "apt update" not in value:
            continue
        # OK if same RUN also has apt-get install / apt install
        if re.search(r"apt(?:-get)?\s+install\b", value):
            continue
        yield Finding(
            id="DFA-030",
            category=CATEGORY,
            severity="low",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="`apt-get update` not chained with install",
            description=(
                "A standalone `RUN apt-get update` creates a cache layer of package metadata. "
                "When a later `RUN apt-get install` runs, it may use stale cached lists, "
                "installing outdated/vulnerable packages."
            ),
            remediation=(
                "Combine update and install in a single RUN, and clean apt cache at the end:\n"
                "`RUN apt-get update && apt-get install -y --no-install-recommends "
                "pkg1 pkg2 && rm -rf /var/lib/apt/lists/*`"
            ),
            fix_dockerfile_snippet=(
                "RUN apt-get update && \\\n"
                "    apt-get install -y --no-install-recommends pkg1 pkg2 && \\\n"
                "    rm -rf /var/lib/apt/lists/*"
            ),
            references=["Hadolint-DL3009"],
        )


@check_meta(id="DFA-031", severity="low", title="apt-get install without --no-install-recommends")
def check_apt_no_recommends(doc: DockerfileDoc) -> Iterable[Finding]:
    install_re = re.compile(r"apt(?:-get)?\s+install\b")
    recommends_re = re.compile(r"--no-install-recommends\b")
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not install_re.search(value):
            continue
        if recommends_re.search(value):
            continue
        yield Finding(
            id="DFA-031",
            category=CATEGORY,
            severity="low",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="`apt-get install` without `--no-install-recommends`",
            description=(
                "Without `--no-install-recommends`, apt pulls in recommended (but not "
                "required) packages, bloating image size by tens to hundreds of MBs."
            ),
            remediation="Add `--no-install-recommends` to all `apt-get install` commands.",
            fix_dockerfile_snippet=(
                "RUN apt-get update && apt-get install -y --no-install-recommends pkg1 pkg2"
            ),
            references=["Hadolint-DL3015"],
        )


@check_meta(id="DFA-032", severity="low", title="pip install without --no-cache-dir")
def check_pip_no_cache(doc: DockerfileDoc) -> Iterable[Finding]:
    pip_re = re.compile(r"\bpip(?:3)?\s+install\b")
    cache_re = re.compile(r"--no-cache-dir\b")
    for inst in doc.iter_instructions("RUN"):
        value = inst.get("value", "")
        if not pip_re.search(value):
            continue
        if cache_re.search(value):
            continue
        # Skip pip install -U pip / setuptools (common, small)
        if re.search(r"pip\s+install\s+(?:-U\s+|--upgrade\s+)?(?:pip|setuptools|wheel)(?:\s|$)", value):
            continue
        yield Finding(
            id="DFA-032",
            category=CATEGORY,
            severity="low",
            instruction="RUN",
            line_number=inst.get("startline", 0) + 1,
            title="`pip install` without `--no-cache-dir`",
            description=(
                "Without `--no-cache-dir`, pip caches downloaded wheels in `~/.cache/pip`. "
                "In a container image, that cache adds size without giving any value back."
            ),
            remediation="Add `--no-cache-dir` to all `pip install` commands.",
            fix_dockerfile_snippet="RUN pip install --no-cache-dir -r requirements.txt",
            references=["Hadolint-DL3042"],
        )


CHECKS = [
    check_apt_update_alone,
    check_apt_no_recommends,
    check_pip_no_cache,
]
