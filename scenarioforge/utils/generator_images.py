"""Which generator images are current, and which are genuinely stale.

A generator image is tagged `coretg-gen-<source-dir>-<service>-<digest>:latest`,
where the digest covers every file that affects the build. That makes the tag
self-validating: a tag that exists cannot be stale, because any edit to the
generator's source produces a different tag. Reusing it is the difference
between a Generate that takes minutes and one that takes seconds, and on an
air-gapped host it is the difference between a Generate that works and one that
cannot fetch its base image at all.

Flow cleanup used to delete **every** `coretg-gen-*` image under the label "old
generator images" -- no age filter, no keep set -- so the cache was guaranteed
empty on the next run and the digest scheme bought nothing. This module supplies
the missing half: given the installed generator sources, it says which images
still correspond to something installed.

Stdlib only, and no imports from the rest of the package: the runner
(`scripts/run_flag_generator.py`) is invoked standalone by path, and the remote
cleanup embeds this file's source into a script that runs on the CORE VM with no
package context. One implementation, three call sites, no room for the cleanup's
idea of a tag to drift from the runner's.
"""

from __future__ import annotations

import hashlib
import os
from typing import Iterable, List, Sequence, Set, Tuple

# Where an installed generator pack lands on the CORE VM. Kept here so the
# cleanup does not have to be told, and so there is one place to change it.
DEFAULT_INSTALLED_ROOTS: Tuple[str, ...] = (
    "/tmp/scenarioforge/outputs/installed_generators/flag_generators",
    "/tmp/scenarioforge/outputs/installed_generators/flag_node_generators",
)

IMAGE_PREFIX = "coretg-gen-"

_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache"}


def slugify(value: str) -> str:
    out = []
    for ch in str(value or "").lower():
        out.append(ch if ch.isalnum() else "-")
    s = "".join(out)
    while "--" in s:
        s = s.replace("--", "-")
    return s.strip("-") or "fg"


def source_cache_digest(source_dir: str) -> str:
    """Short digest over every file that affects the generator image.

    Mirrors the build inputs exactly: the generated per-run
    `docker-compose.hostnet.*` files are excluded because they are written on
    each run and would otherwise change the digest every time, defeating the
    cache this digest exists to enable.
    """
    root = os.path.abspath(source_dir)
    digest = hashlib.sha256()
    entries: List[Tuple[str, str]] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if set(rel.split("/")) & _SKIP_DIRS:
                continue
            if name.startswith("docker-compose.hostnet.") and name.endswith((".yml", ".yaml")):
                continue
            if name.endswith((".pyc", ".pyo")):
                continue
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            entries.append((rel, full))
    for rel, full in sorted(entries, key=lambda pair: pair[0]):
        try:
            with open(full, "rb") as handle:
                data = handle.read()
        except Exception:
            continue
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(data)
        digest.update(b"\0")
    return digest.hexdigest()[:12]


def image_tag(source_dir: str, service: str, digest: str | None = None) -> str:
    """The stable tag the runner builds for one compose service."""
    resolved = digest if digest is not None else source_cache_digest(source_dir)
    return f"{IMAGE_PREFIX}{slugify(os.path.basename(os.path.abspath(source_dir)))}-{slugify(service)}-{resolved}:latest"


def installed_source_dirs(roots: Sequence[str] | None = None) -> List[str]:
    """Every installed generator source directory under the given roots."""
    out: List[str] = []
    for root in (roots if roots is not None else DEFAULT_INSTALLED_ROOTS):
        try:
            names = sorted(os.listdir(root))
        except Exception:
            continue
        for name in names:
            path = os.path.join(root, name)
            if os.path.isdir(path) and not os.path.islink(path):
                out.append(path)
    return out


def current_image_markers(roots: Sequence[str] | None = None) -> Set[Tuple[str, str]]:
    """`(tag-prefix, digest)` for every installed generator.

    The service name is deliberately not resolved: doing so would mean parsing
    each compose file, and the prefix plus digest already identify an image
    uniquely enough to keep. A generator with several services contributes one
    marker that covers all of them.
    """
    markers: Set[Tuple[str, str]] = set()
    for source_dir in installed_source_dirs(roots):
        try:
            digest = source_cache_digest(source_dir)
        except Exception:
            continue
        prefix = f"{IMAGE_PREFIX}{slugify(os.path.basename(source_dir))}-"
        markers.add((prefix, digest))
    return markers


def is_current(tag: str, markers: Iterable[Tuple[str, str]]) -> bool:
    text = str(tag or "").strip()
    if not text.startswith(IMAGE_PREFIX):
        return False
    repository = text.split(":", 1)[0]
    for prefix, digest in markers:
        if repository.startswith(prefix) and repository.endswith(f"-{digest}"):
            return True
    return False


def stale_images(tags: Iterable[str], roots: Sequence[str] | None = None) -> List[str]:
    """The `coretg-gen-*` tags safe to delete: no installed source produces them.

    Anything that is not a generator image is left out entirely rather than
    reported as stale — this function decides only about images it understands.
    """
    markers = current_image_markers(roots)
    out: List[str] = []
    for tag in tags:
        text = str(tag or "").strip()
        if not text.startswith(IMAGE_PREFIX):
            continue
        if not is_current(text, markers):
            out.append(text)
    return out
