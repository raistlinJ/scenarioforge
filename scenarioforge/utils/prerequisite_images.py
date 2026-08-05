"""Container images ScenarioForge itself needs, as opposed to scenario content.

An operator choosing a lab decides which vulnerabilities and generators are in
it, and on an air-gapped host they pre-seed those. They should not also have to
discover that the framework quietly needs a busybox to build a wrapper, an
ubuntu for the standard node, an alpine to copy inject files in, and a python
for its own generator templates. Those are plumbing: this module names them so
they are kept and prepared by default, leaving only the scenario's own content
for the operator to seed.

Two sources, deliberately:

* constants in code, where the image is baked into a build step;
* the repo's own compose templates, so a template added later registers its base
  image here without anyone remembering to.

Each is overridable by the same environment variable that overrides it at the
point of use, so a site mirroring its own registry gets *its* images kept and
prepared rather than the upstream ones.
"""

from __future__ import annotations

import logging
import os
import re
from typing import List

logger = logging.getLogger(__name__)

# Compose templates that ship with the repo. Their `image:` values are framework
# prerequisites; a scenario's own vulnerability compose files are not.
_TEMPLATE_GLOBS: tuple[str, ...] = (
    "scripts/*/docker-compose.yml",
    "generator_templates/*/docker-compose.yml",
)

_IMAGE_LINE = re.compile(r"^\s*image:\s*(?P<image>\S+)\s*$", re.MULTILINE)


def _repo_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _from_code() -> List[str]:
    """Images named by a constant because a build step is built `FROM` them."""
    out: List[str] = []

    try:
        from ..builders.topology import _BUSYBOX_REPAIR_IMAGE
        out.append(str(_BUSYBOX_REPAIR_IMAGE or ""))
    except Exception as exc:
        logger.debug("Prerequisite images: wrapper base unavailable: %s", exc)

    try:
        from .pivot_access import PIVOT_SSH_IMAGE
        out.append(str(PIVOT_SSH_IMAGE or ""))
    except Exception as exc:
        logger.debug("Prerequisite images: pivot provider image unavailable: %s", exc)

    # Both read their override at the point of use, so read it the same way here
    # rather than pinning an upstream image a site has replaced.
    out.append(str(os.getenv("CORETG_INJECT_COPY_IMAGE") or "").strip() or "alpine:3.19")
    out.append(
        str(os.getenv("CORETG_NFS_GANESHA_WRAPPER_BASE_IMAGE") or "").strip() or "ubuntu:22.04"
    )
    return out


def _from_templates() -> List[str]:
    """Images the repo's own compose templates are built on."""
    import glob

    out: List[str] = []
    root = _repo_root()
    for pattern in _TEMPLATE_GLOBS:
        for path in sorted(glob.glob(os.path.join(root, pattern))):
            try:
                with open(path, "r", encoding="utf-8") as handle:
                    text = handle.read()
            except Exception as exc:
                logger.debug("Prerequisite images: could not read %s: %s", path, exc)
                continue
            for match in _IMAGE_LINE.finditer(text):
                image = match.group("image").strip().strip("'\"")
                # An interpolated image is resolved per run, so it is not a
                # fixed prerequisite anything could pre-seed.
                if image and "$" not in image:
                    out.append(image)
    return out


def prerequisite_images() -> List[str]:
    """Every image the framework needs before a scenario's own content.

    Order is stable and duplicates are dropped, so callers can log it or diff it
    between runs.
    """
    seen: List[str] = []
    for image in _from_code() + _from_templates():
        text = str(image or "").strip()
        if text and text not in seen:
            seen.append(text)
    return seen
