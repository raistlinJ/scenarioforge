"""Vulnerability capability metadata.

A vulnerability catalog entry (a vulhub-style compose directory) only tells us
how to *deploy* a target.  It says nothing about what a solver actually gains by
exploiting it, so Flow could previously place a generator requiring
``CodeExecution(host)`` behind a read-only path-traversal CVE and still call the
chain valid.

This module reads a companion metadata file that declares, in the same fact
vocabulary generators already use, what a vulnerability *requires* to be
exploitable and what it *provides* once exploited.  Those facts are fed into the
flag-sequencing solver so a chain is only built when every step is reachable.

Resolution order (most specific wins):

1. ``<vuln_dir>/scenarioforge.vuln.yaml`` -- travels with the pack entry.
2. ``<catalog_pack_dir>/vuln_metadata.yaml`` -- one file per installed catalog.
3. ``<repo_root>/vuln_metadata.yaml`` -- site-wide fallback.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from scenarioforge.sequencer.facts import load_fact_ontology, validate_fact_ref

try:  # pragma: no cover - exercised indirectly when PyYAML is absent
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


SCHEMA_VERSION = 1

# Per-vuln-directory filenames, in preference order.
_ENTRY_FILENAMES: Tuple[str, ...] = (
    'scenarioforge.vuln.yaml',
    'scenarioforge.vuln.yml',
    'scenarioforge.vuln.json',
)

# Catalog-level and repo-level filenames, in preference order.
_INDEX_FILENAMES: Tuple[str, ...] = (
    'vuln_metadata.yaml',
    'vuln_metadata.yml',
    'vuln_metadata.json',
)


def metadata_filenames() -> Dict[str, Tuple[str, ...]]:
    """Filenames recognized at each level, for docs and scaffolding."""
    return {'entry': _ENTRY_FILENAMES, 'index': _INDEX_FILENAMES}


# ---------------------------------------------------------------------------
# Impact taxonomy
# ---------------------------------------------------------------------------

# Shorthand so an author can write `impact: remote_code_execution` instead of
# spelling out facts.  Explicit `provides`/`requires` are unioned on top.
IMPACT_PROVIDES: Dict[str, Tuple[str, ...]] = {
    'remote_code_execution': ('CodeExecution(host)', 'Shell(host)'),
    'command_injection': ('CodeExecution(host)', 'Shell(host)'),
    'deserialization': ('CodeExecution(host)', 'Shell(host)'),
    'web_rce': ('WebRCE(app)', 'CodeExecution(host)', 'Shell(host)'),
    'privilege_escalation': ('RootShell(host)',),
    'auth_bypass': ('WebAuthBypass(app)',),
    'arbitrary_file_read': ('File(host, path)',),
    'path_traversal': ('File(host, path)',),
    'arbitrary_file_write': ('File(host, path)',),
    'arbitrary_file_upload': ('UploadPrimitive(app)', 'File(host, path)'),
    'sql_injection': ('Knowledge(type, value)', 'Credential(user, hash)'),
    'credential_disclosure': ('Credential(user, password)',),
    'secret_disclosure': ('ExposedSecret(service)',),
    'information_disclosure': ('Knowledge(value)',),
    'ssrf': ('NetworkAccess(src, dst, port)',),
    'xxe': ('File(host, path)',),
    'misconfiguration': ('Misconfiguration(service)',),
    # Deliberately grant nothing: these do not advance a chain.
    'denial_of_service': (),
    'unknown': (),
}

# Facts an impact class needs before it can be exploited at all.
IMPACT_REQUIRES: Dict[str, Tuple[str, ...]] = {
    'privilege_escalation': ('Shell(host)',),
}

# `provides` subsumption: holding the key fact also grants the listed facts.
# Kept small and defensible -- these are implications a solver can rely on.
_SUBSUMES: Dict[str, Tuple[str, ...]] = {
    'RootShell(host)': ('Shell(host)', 'CodeExecution(host)'),
    'Shell(host)': ('CodeExecution(host)',),
    'WebRCE(app)': ('CodeExecution(host)',),
}


def known_impacts() -> Tuple[str, ...]:
    return tuple(sorted(IMPACT_PROVIDES))


# ---------------------------------------------------------------------------
# Fact canonicalization
# ---------------------------------------------------------------------------

_FACT_RE = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\((.*)\)\s*$', re.DOTALL)


def canonical_fact_key(value: Any) -> str:
    """Return a spelling-insensitive key for a fact reference.

    Generators in the wild write both ``Credential(user,password)`` and
    ``Credential(user, password)``.  The existing solver compares fact strings
    literally, so those two never match.  Vuln facts are matched through this
    key instead, and re-expanded to the generator's own spelling before they
    enter solver state (see :func:`expand_provided_facts`).

    Arity is preserved: ``Shell(host)`` and ``Shell(host, user)`` stay distinct
    because the ontology treats them as separate signatures.
    """
    raw = str(value or '').strip()
    if not raw:
        return ''
    match = _FACT_RE.match(raw)
    if not match:
        return raw.lower()
    name = match.group(1).strip()
    args_raw = match.group(2).strip()
    if not args_raw:
        return f'{name}()'
    args = [part.strip().lower() for part in args_raw.split(',')]
    args = [part for part in args if part]
    return f'{name}({",".join(args)})'


def _canonical_set(values: Iterable[Any]) -> Set[str]:
    out: Set[str] = set()
    for value in values or []:
        key = canonical_fact_key(value)
        if key:
            out.add(key)
    return out


def _apply_subsumption(canonical: Set[str]) -> Set[str]:
    """Close a canonical fact set under the subsumption table."""
    resolved = set(canonical)
    pending = list(resolved)
    subsumes_canonical = {
        canonical_fact_key(key): tuple(canonical_fact_key(v) for v in values)
        for key, values in _SUBSUMES.items()
    }
    while pending:
        current = pending.pop()
        for implied in subsumes_canonical.get(current, ()):  # noqa: B007
            if implied and implied not in resolved:
                resolved.add(implied)
                pending.append(implied)
    return resolved


def expand_provided_facts(
    canonical_provides: Iterable[str],
    vocabulary: Iterable[str],
) -> Set[str]:
    """Re-spell canonical vuln facts using the vocabulary's literal strings.

    ``vocabulary`` is every fact string the generators actually declare.  The
    solver compares literally, so a vuln providing ``Shell(host)`` must enter
    state using whatever spelling the consuming generator wrote.  Any canonical
    fact with no vocabulary match is still emitted in its canonical form so it
    remains inspectable.
    """
    wanted = _apply_subsumption(_canonical_set(canonical_provides))
    if not wanted:
        return set()

    by_key: Dict[str, Set[str]] = {}
    for term in vocabulary or []:
        literal = str(term or '').strip()
        if not literal:
            continue
        by_key.setdefault(canonical_fact_key(literal), set()).add(literal)

    out: Set[str] = set()
    for key in wanted:
        matches = by_key.get(key)
        if matches:
            out |= matches
        else:
            out.add(key)
    return out


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class VulnFacts:
    """What exploiting one vulnerability costs and yields."""

    key: str
    impact: str = 'unknown'
    requires: Tuple[str, ...] = ()
    provides: Tuple[str, ...] = ()
    cve: str = ''
    notes: str = ''
    source_path: str = ''

    @property
    def canonical_requires(self) -> Set[str]:
        return _canonical_set(self.requires)

    @property
    def canonical_provides(self) -> Set[str]:
        return _apply_subsumption(_canonical_set(self.provides))

    def is_empty(self) -> bool:
        return not self.requires and not self.provides


@dataclass
class VulnMetadataIndex:
    """Resolved vulnerability metadata for one or more catalogs."""

    exact: Dict[str, VulnFacts] = field(default_factory=dict)
    patterns: List[Tuple[str, VulnFacts]] = field(default_factory=list)
    by_cve: Dict[str, VulnFacts] = field(default_factory=dict)
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.exact or self.patterns or self.by_cve)

    def lookup(self, *names: Any) -> Optional[VulnFacts]:
        """Resolve the first of ``names`` that matches an entry.

        Tries exact match, then CVE match, then glob patterns.  Matching is
        case-insensitive and tolerant of ``\\`` vs ``/`` separators, because a
        vuln reaches us as a display name, a rel_dir, or a bare CVE id.
        """
        candidates = [_normalize_lookup_name(name) for name in names]
        candidates = [name for name in candidates if name]
        if not candidates:
            return None

        for name in candidates:
            hit = self.exact.get(name)
            if hit is not None:
                return hit

        # A rel_dir like "vulhub/activemq/CVE-2015-5254" should also match an
        # entry keyed on just "activemq/CVE-2015-5254" or the bare CVE.
        for name in candidates:
            for suffix in _name_suffixes(name):
                hit = self.exact.get(suffix)
                if hit is not None:
                    return hit

        for name in candidates:
            for token in _cve_tokens(name):
                hit = self.by_cve.get(token)
                if hit is not None:
                    return hit

        for name in candidates:
            for pattern, facts in self.patterns:
                if fnmatch.fnmatch(name, pattern):
                    return facts
        return None

    def merge(self, other: 'VulnMetadataIndex') -> None:
        """Merge ``other`` in as *lower* priority than what is already here."""
        for key, value in other.exact.items():
            self.exact.setdefault(key, value)
        for key, value in other.by_cve.items():
            self.by_cve.setdefault(key, value)
        existing_patterns = {pattern for pattern, _ in self.patterns}
        for pattern, value in other.patterns:
            if pattern not in existing_patterns:
                self.patterns.append((pattern, value))
        self.sources.extend(other.sources)
        self.errors.extend(other.errors)


def _normalize_lookup_name(value: Any) -> str:
    text = str(value or '').strip().replace('\\', '/').strip('/')
    return text.lower()


def _name_suffixes(name: str) -> List[str]:
    parts = [part for part in name.split('/') if part]
    out: List[str] = []
    for start in range(1, len(parts)):
        out.append('/'.join(parts[start:]))
    return out


_CVE_RE = re.compile(r'(cve-\d{4}-\d{4,})', re.IGNORECASE)


def _cve_tokens(name: str) -> List[str]:
    return [match.lower() for match in _CVE_RE.findall(name or '')]


# ---------------------------------------------------------------------------
# Document parsing and validation
# ---------------------------------------------------------------------------


def _load_doc(path: Path) -> Optional[Any]:
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeDecodeError):
        return None
    suffix = path.suffix.lower()
    if suffix == '.json':
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None
    if yaml is None:
        return None
    try:
        return yaml.safe_load(text)
    except Exception:
        return None


def _as_str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        return []
    out: List[str] = []
    for item in items:
        if isinstance(item, dict):
            for key in ('artifact', 'fact', 'name'):
                inner = item.get(key)
                if isinstance(inner, str) and inner.strip():
                    out.append(inner.strip())
                    break
            continue
        text = str(item or '').strip()
        if text:
            out.append(text)
    return out


def validate_vuln_metadata_doc(
    doc: Any,
    *,
    source: str = '',
    ontology: Optional[Dict[str, Set[int]]] = None,
) -> Tuple[List[VulnFacts], List[str]]:
    """Validate one metadata document into records plus error strings."""
    errors: List[str] = []
    prefix = f'{source}: ' if source else ''

    if not isinstance(doc, dict):
        return [], [f'{prefix}metadata must be a mapping at the document root']

    version = doc.get('schema_version', SCHEMA_VERSION)
    try:
        version_int = int(version)
    except (TypeError, ValueError):
        version_int = -1
    if version_int != SCHEMA_VERSION:
        errors.append(
            f'{prefix}unsupported schema_version {version!r} (expected {SCHEMA_VERSION})'
        )
        return [], errors

    raw_entries = doc.get('vulns')
    if raw_entries is None:
        # A per-vuln-directory file may hold a single bare entry.
        if any(key in doc for key in ('match', 'impact', 'provides', 'requires', 'cve')):
            raw_entries = [doc]
        else:
            raw_entries = []
    if not isinstance(raw_entries, list):
        return [], [f'{prefix}vulns must be a list']

    ont = ontology if ontology is not None else load_fact_ontology()
    records: List[VulnFacts] = []

    for idx, raw in enumerate(raw_entries):
        label = f'{prefix}vulns[{idx}]'
        if not isinstance(raw, dict):
            errors.append(f'{label} must be a mapping')
            continue

        match_value = raw.get('match') or raw.get('name') or raw.get('id') or ''
        cve_value = str(raw.get('cve') or '').strip()
        key = str(match_value or '').strip()
        if not key and not cve_value:
            errors.append(f'{label} needs a "match" or "cve"')
            continue

        impact = str(raw.get('impact') or 'unknown').strip().lower() or 'unknown'
        if impact not in IMPACT_PROVIDES:
            errors.append(
                f'{label} unknown impact {impact!r}; expected one of '
                + ', '.join(known_impacts())
            )
            continue

        provides = list(IMPACT_PROVIDES.get(impact, ()))
        provides.extend(_as_str_list(raw.get('provides')))
        requires = list(IMPACT_REQUIRES.get(impact, ()))
        requires.extend(_as_str_list(raw.get('requires')))

        bad_fact = False
        for bucket_name, bucket in (('provides', provides), ('requires', requires)):
            for fact in bucket:
                fact_error = validate_fact_ref(fact, ontology=ont)
                if fact_error:
                    errors.append(f'{label}.{bucket_name} {fact!r}: {fact_error}')
                    bad_fact = True
        if bad_fact:
            continue

        records.append(
            VulnFacts(
                key=key or cve_value,
                impact=impact,
                requires=tuple(dict.fromkeys(requires)),
                provides=tuple(dict.fromkeys(provides)),
                cve=cve_value,
                notes=str(raw.get('notes') or '').strip(),
                source_path=source,
            )
        )

    return records, errors


def _index_from_records(records: Sequence[VulnFacts], *, source: str) -> VulnMetadataIndex:
    index = VulnMetadataIndex(sources=[source] if source else [])
    for record in records:
        key = _normalize_lookup_name(record.key)
        if key:
            if any(ch in key for ch in '*?['):
                index.patterns.append((key, record))
            else:
                index.exact.setdefault(key, record)
        if record.cve:
            index.by_cve.setdefault(record.cve.strip().lower(), record)
    return index


def load_vuln_metadata_file(path: str | Path) -> VulnMetadataIndex:
    """Load a single metadata file into an index."""
    p = Path(path)
    doc = _load_doc(p)
    if doc is None:
        return VulnMetadataIndex(errors=[f'{p}: unreadable or malformed metadata file'])
    records, errors = validate_vuln_metadata_doc(doc, source=str(p))
    index = _index_from_records(records, source=str(p))
    index.errors.extend(errors)
    return index


def _first_existing(directory: str | Path, filenames: Sequence[str]) -> Optional[Path]:
    base = Path(directory)
    for name in filenames:
        candidate = base / name
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def load_vuln_metadata_index(
    *,
    entry_dirs: Optional[Sequence[str | Path]] = None,
    catalog_dirs: Optional[Sequence[str | Path]] = None,
    repo_root: Optional[str | Path] = None,
) -> VulnMetadataIndex:
    """Build a merged index across all three resolution levels.

    Earlier levels win: a per-vuln file overrides its catalog file, which
    overrides the repo-level file.
    """
    merged = VulnMetadataIndex()

    for directory in (entry_dirs or []):
        found = _first_existing(directory, _ENTRY_FILENAMES)
        if found is None:
            continue
        loaded = load_vuln_metadata_file(found)
        # A per-directory file may omit `match`; key it to the directory name.
        if loaded.exact or loaded.patterns or loaded.by_cve:
            merged.merge(loaded)
        else:
            merged.errors.extend(loaded.errors)
            continue
        try:
            dir_key = _normalize_lookup_name(Path(directory).name)
        except Exception:
            dir_key = ''
        if dir_key:
            for record in list(loaded.exact.values()) + [r for _, r in loaded.patterns]:
                merged.exact.setdefault(dir_key, record)
                break

    for directory in (catalog_dirs or []):
        found = _first_existing(directory, _INDEX_FILENAMES)
        if found is not None:
            merged.merge(load_vuln_metadata_file(found))

    if repo_root:
        found = _first_existing(repo_root, _INDEX_FILENAMES)
        if found is not None:
            merged.merge(load_vuln_metadata_file(found))

    return merged
