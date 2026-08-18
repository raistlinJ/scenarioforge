"""What CPU architectures a catalog item's images can actually run on.

Why this matters: a vulhub recipe pinning an amd64-only image runs on an arm64
CORE VM only under qemu emulation, and heavy applications do not survive that.
A real run had two Confluence nodes exit 139 (SIGSEGV) mid-boot, restart, and
lose the addressing CORE applies at execute -- which failed the whole scenario
for a reason that looked like a networking fault. Recording the architectures
up front lets the catalog say so instead.

Three sources, cheapest and most authoritative first:

* ``declared``  -- an explicit ``platform:`` in the compose file. The author
  said it outright, and it overrides whatever the registry offers.
* ``local``     -- ``docker image inspect`` on an image already pulled here.
  No network, and it is the architecture this host would actually run.
* ``registry``  -- ``docker manifest inspect``. Authoritative and complete, but
  needs network and registry quota, so it is the last resort and is allowed to
  fail without taking anything else down.

Every result carries the source it came from, so a caller can tell "known to be
amd64-only" from "nobody has looked yet". Nothing here raises: an architecture
that cannot be determined is reported as unknown, never guessed, because the
consequence of a wrong answer is a silently excluded catalog entry.

The results are meant to be persisted and carried through catalog export, since
an air-gapped CORE host cannot reach a registry to work them out for itself.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from typing import Any, Iterable

logger = logging.getLogger(__name__)

UNKNOWN = "unknown"

# Keep these small: catalog installs call this once per image across a few
# hundred entries, and a registry that is slow or rate-limiting must not stall
# the install.
_LOCAL_TIMEOUT_S = 10.0
_REGISTRY_TIMEOUT_S = 15.0

# Importing a generator repository scans one compose file per generator, and
# generators overwhelmingly share a handful of base images. Without this, an
# 80-generator repo ran `docker manifest inspect` 80+ times for the same few
# refs -- about 2.2s each, so the install took minutes and looked hung. Results
# are memoized per image ref so each distinct image is resolved once.
#
# Unresolved answers expire quickly: an image that could not be reached because
# the registry was briefly unavailable, or that has since been pulled locally,
# must not stay "unknown" for the life of a long-running webapp process.
_CACHE_TTL_RESOLVED_S = 900.0
_CACHE_TTL_UNRESOLVED_S = 60.0

_arch_cache: dict[tuple[str, bool], tuple[float, list[str], str]] = {}


def clear_image_architecture_cache() -> None:
    """Drop memoized architecture lookups (tests, and after pulling images)."""
    _arch_cache.clear()


def _docker_available() -> bool:
    try:
        import shutil

        return bool(shutil.which("docker"))
    except Exception:
        return False


def _run(args: list[str], timeout_s: float) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, timeout=timeout_s,
        )
        return int(proc.returncode), str(proc.stdout or "")
    except Exception:
        return 1, ""


def normalize_architecture(value: Any) -> str:
    """Canonical architecture name.

    Docker reports `amd64`/`arm64`; users and `uname` say `x86_64`/`aarch64`.
    Normalizing means a catalog scanned on one machine compares correctly
    against a host that describes itself differently.
    """
    text = str(value or "").strip().lower()
    if not text:
        return ""
    text = text.split("/")[-1] if text.startswith("linux/") else text
    aliases = {
        "x86_64": "amd64",
        "x86-64": "amd64",
        "x64": "amd64",
        "aarch64": "arm64",
        "armv8": "arm64",
        "armv8l": "arm64",
        "i386": "386",
        "i686": "386",
    }
    return aliases.get(text, text)


def host_architecture() -> str:
    """This machine's architecture, normalized (best-effort)."""
    try:
        import platform

        return normalize_architecture(platform.machine())
    except Exception:
        return ""


def compose_image_refs(compose_obj: Any) -> list[str]:
    """Image references a compose stack pulls, in stable order.

    Services that only ``build:`` have no pullable image and contribute
    nothing here -- their architecture follows whatever the build host is.
    """
    if not isinstance(compose_obj, dict):
        return []
    services = compose_obj.get("services")
    if not isinstance(services, dict):
        return []
    out: list[str] = []
    for _name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        image = str(svc.get("image") or "").strip()
        if image and "$" not in image and image not in out:
            out.append(image)
    return out


def dockerfile_base_images(text: str) -> list[str]:
    """Base images a Dockerfile pulls, in stable order.

    Skips two things that are not pullable references: a ``FROM`` naming an
    earlier build stage, and one parameterised by an ARG, which cannot be
    resolved without performing the build.
    """
    stages: set[str] = set()
    out: list[str] = []
    for match in re.finditer(
        r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", str(text or ""), re.M
    ):
        ref = str(match.group(1) or "").strip()
        alias = str(match.group(2) or "").strip()
        if alias:
            stages.add(alias.lower())
        if not ref or "$" in ref or ref.lower() in stages:
            continue
        if ref not in out:
            out.append(ref)
    return out


def compose_build_base_images(compose_obj: Any, base_dir: str) -> list[str]:
    """Base images the stack's own Dockerfiles pull.

    A service that only ``build:``s has no pullable image, but the image it
    produces still inherits its base. Reading that base is the difference
    between "not checked" and a real answer for a build-only stack.
    """
    if not isinstance(compose_obj, dict) or not base_dir:
        return []
    services = compose_obj.get("services")
    if not isinstance(services, dict):
        return []
    out: list[str] = []
    for _name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        build = svc.get("build")
        if build is None:
            continue
        if isinstance(build, str):
            context, dockerfile = build, "Dockerfile"
        elif isinstance(build, dict):
            context = str(build.get("context") or ".")
            dockerfile = str(build.get("dockerfile") or "Dockerfile")
        else:
            continue
        if "$" in context or "$" in dockerfile:
            continue
        path = os.path.normpath(os.path.join(base_dir, context, dockerfile))
        try:
            if not os.path.isfile(path):
                continue
            with open(path, "r", encoding="utf-8", errors="ignore") as handle:
                text = handle.read()
        except OSError:
            continue
        for ref in dockerfile_base_images(text):
            if ref not in out:
                out.append(ref)
    return out


def compose_declared_platforms(compose_obj: Any) -> list[str]:
    """Architectures the compose file pins explicitly via ``platform:``."""
    if not isinstance(compose_obj, dict):
        return []
    services = compose_obj.get("services")
    if not isinstance(services, dict):
        return []
    found: list[str] = []
    for _name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        arch = normalize_architecture(svc.get("platform"))
        if arch and arch not in found:
            found.append(arch)
    return found


def _architectures_from_local(image: str) -> list[str]:
    rc, out = _run(
        ["docker", "image", "inspect", "--format", "{{.Architecture}}", image],
        _LOCAL_TIMEOUT_S,
    )
    if rc != 0:
        return []
    arch = normalize_architecture(out.strip().splitlines()[0] if out.strip() else "")
    return [arch] if arch else []


def _architectures_from_registry(image: str) -> list[str]:
    rc, out = _run(["docker", "manifest", "inspect", image], _REGISTRY_TIMEOUT_S)
    if rc != 0 or not out.strip():
        return []
    try:
        doc = json.loads(out)
    except Exception:
        return []
    found: list[str] = []
    manifests = doc.get("manifests") if isinstance(doc, dict) else None
    if isinstance(manifests, list):
        for entry in manifests:
            if not isinstance(entry, dict):
                continue
            arch = normalize_architecture((entry.get("platform") or {}).get("architecture"))
            # Buildx attestation manifests report `unknown`; they are metadata,
            # not runnable images.
            if arch and arch != UNKNOWN and arch not in found:
                found.append(arch)
    if found:
        return found
    # A single-arch image has no manifest list; its architecture only appears
    # in the verbose form's descriptor.
    rc2, out2 = _run(["docker", "manifest", "inspect", "-v", image], _REGISTRY_TIMEOUT_S)
    if rc2 != 0 or not out2.strip():
        return []
    try:
        doc2 = json.loads(out2)
    except Exception:
        return []
    entries = doc2 if isinstance(doc2, list) else [doc2]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        platform_info = (entry.get("Descriptor") or {}).get("platform") or {}
        arch = normalize_architecture(platform_info.get("architecture"))
        if arch and arch != UNKNOWN and arch not in found:
            found.append(arch)
    return found


def image_architectures(image: str, *, allow_registry: bool = True) -> tuple[list[str], str]:
    """(architectures, source) for one image reference.

    Returns an empty list with source ``unknown`` when nothing could determine
    it -- never a guess, since an unsupported-architecture verdict decides
    whether an operator sees the item at all.
    """
    ref = str(image or "").strip()
    if not ref or not _docker_available():
        return [], UNKNOWN

    key = (ref, bool(allow_registry))
    now = time.monotonic()
    cached = _arch_cache.get(key)
    if cached is not None:
        cached_at, cached_archs, cached_source = cached
        ttl = _CACHE_TTL_RESOLVED_S if cached_archs else _CACHE_TTL_UNRESOLVED_S
        if (now - cached_at) < ttl:
            return list(cached_archs), cached_source

    archs: list[str] = []
    source = UNKNOWN
    local = _architectures_from_local(ref)
    if local:
        archs, source = local, "local"
    elif allow_registry:
        registry = _architectures_from_registry(ref)
        if registry:
            archs, source = registry, "registry"

    _arch_cache[key] = (now, list(archs), source)
    return list(archs), source


def compose_architectures(
    compose_obj: Any, *, allow_registry: bool = True, base_dir: str | None = None
) -> dict[str, Any]:
    """Architectures a whole compose stack can run on.

    A stack runs natively only where *every* one of its images does, so the
    result is the intersection across images -- one amd64-only sidecar is
    enough to make the node need emulation.

    Returns ``{architectures, source, per_image, unresolved}``. ``source`` is
    ``unknown`` when nothing was resolvable, which callers must treat as "not
    yet known" rather than "runs nowhere".
    """
    declared = compose_declared_platforms(compose_obj)
    if declared:
        return {
            "architectures": sorted(declared),
            "source": "declared",
            "per_image": {},
            "unresolved": [],
        }

    refs = compose_image_refs(compose_obj)
    from_build = False
    if not refs and base_dir:
        # A build-only stack has no pinned image, but the image it produces
        # inherits its Dockerfile's base -- which is a real, checkable answer.
        # Without this the whole stack reported as unknown, which reads the same
        # as "never scanned" and hides an amd64-only base behind a neutral badge.
        refs = compose_build_base_images(compose_obj, base_dir)
        from_build = bool(refs)
    if not refs:
        return {"architectures": [], "source": UNKNOWN, "per_image": {}, "unresolved": []}

    per_image: dict[str, list[str]] = {}
    unresolved: list[str] = []
    sources: set[str] = set()
    for ref in refs:
        archs, source = image_architectures(ref, allow_registry=allow_registry)
        if archs:
            per_image[ref] = archs
            sources.add(source)
        else:
            unresolved.append(ref)

    if not per_image:
        return {"architectures": [], "source": UNKNOWN, "per_image": {}, "unresolved": unresolved}

    common: set[str] | None = None
    for archs in per_image.values():
        common = set(archs) if common is None else (common & set(archs))
    # Prefer the weaker claim when some images could not be resolved: what we
    # know is only about the images we could actually see.
    source = "registry" if "registry" in sources else ("local" if "local" in sources else UNKNOWN)
    if from_build and source != UNKNOWN:
        # Say where the answer came from: these are the architectures the stack
        # can be *built* natively on, not those of a published image.
        source = "build-base"
    if unresolved:
        source = f"partial-{source}"
    return {
        "architectures": sorted(common or set()),
        "source": source,
        "per_image": per_image,
        "unresolved": unresolved,
    }


def architecture_summary_for_compose_file(
    compose_path: str, *, allow_registry: bool = True
) -> dict[str, Any]:
    """Architecture summary for a compose file on disk, safe to call anywhere."""
    empty = {"architectures": [], "source": UNKNOWN, "per_image": {}, "unresolved": []}
    try:
        if not compose_path or not os.path.exists(compose_path):
            return empty
        import yaml  # type: ignore

        with open(compose_path, "r", encoding="utf-8", errors="ignore") as handle:
            compose_obj = yaml.safe_load(handle)
        return compose_architectures(
            compose_obj,
            allow_registry=allow_registry,
            base_dir=os.path.dirname(os.path.abspath(compose_path)),
        )
    except Exception as exc:
        logger.debug("architecture scan failed for %s: %s", compose_path, exc)
        return empty


def summary_runs_natively(summary: Any, host_arch: str | None = None) -> bool | None:
    """Whether a `compose_architectures` summary says this host runs it natively.

    Distinguishes the two ways an architecture list comes back empty, which the
    list alone cannot express:

    * nothing was resolvable (``source: unknown``) -> ``None``, not yet known;
    * images resolved but share no common architecture -> ``False``, this stack
      needs emulation for at least one of its images wherever it runs.

    Conflating them would either hide a genuinely emulated stack or disable an
    entire unscanned catalog.
    """
    if not isinstance(summary, dict):
        return None
    archs = [normalize_architecture(a) for a in (summary.get("architectures") or [])]
    archs = [a for a in archs if a]
    if archs:
        return runs_natively_on(archs, host_arch)
    if summary.get("per_image"):
        # Resolved, but no architecture satisfies every image.
        return False
    return None


def runs_natively_on(architectures: Iterable[Any], host_arch: str | None = None) -> bool | None:
    """Whether a known architecture set includes this host.

    ``None`` means "not known" -- an empty/unscanned set must never read as
    "does not run here", or an unscanned catalog would disable itself wholesale.
    """
    known = [normalize_architecture(a) for a in (architectures or [])]
    known = [a for a in known if a]
    if not known:
        return None
    host = normalize_architecture(host_arch) if host_arch else host_architecture()
    if not host:
        return None
    return host in known
