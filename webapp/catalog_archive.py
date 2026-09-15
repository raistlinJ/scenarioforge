"""Shared metadata discovery for generator and vulnerability archives."""


def read_archive_metadata(archive, relative_path):
    """Read metadata at the root or under a wrapper; return text and wrapper.

    Prefer the shallowest metadata, so an outer catalog owns its nested files.
    Equally shallow alternatives are ambiguous and must not be picked silently.
    Missing optional metadata raises KeyError.
    """
    candidates = []
    for original in archive.namelist():
        name = original.replace('\\', '/')
        if name.startswith('/') or '..' in name.split('/') or name.startswith('__MACOSX/'):
            continue
        if name == relative_path or name.endswith('/' + relative_path):
            prefix = name[:-len(relative_path)]
            candidates.append((prefix.count('/'), original, prefix))
    if not candidates:
        raise KeyError(relative_path)
    depth = min(item[0] for item in candidates)
    nearest = [item for item in candidates if item[0] == depth]
    if len(nearest) != 1:
        raise ValueError(f'Ambiguous catalog metadata: {relative_path}')
    _, original, prefix = nearest[0]
    return archive.read(original).decode('utf-8'), prefix
