from __future__ import annotations

from .metadata import (
    IMPACT_PROVIDES,
    IMPACT_REQUIRES,
    VulnFacts,
    VulnMetadataIndex,
    canonical_fact_key,
    expand_provided_facts,
    known_impacts,
    load_vuln_metadata_file,
    load_vuln_metadata_index,
    metadata_filenames,
    validate_vuln_metadata_doc,
)

__all__ = [
    'IMPACT_PROVIDES',
    'IMPACT_REQUIRES',
    'VulnFacts',
    'VulnMetadataIndex',
    'canonical_fact_key',
    'expand_provided_facts',
    'known_impacts',
    'load_vuln_metadata_file',
    'load_vuln_metadata_index',
    'metadata_filenames',
    'validate_vuln_metadata_doc',
]
