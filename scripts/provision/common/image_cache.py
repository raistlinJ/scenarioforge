"""Remember verified cloud images and require an existing image for reinstalls."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request


class MissingCachedImage(ValueError):
    """An absent cache entry, as distinct from an invalid existing image."""


def digest(path, algorithm):
    with Path(path).open('rb') as stream:
        value = hashlib.new(algorithm)
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        return value.hexdigest()


def remember(path, url, algorithm, checksum):
    record = Path(str(path) + '.verified.json')
    temporary = record.with_suffix('.tmp')
    temporary.write_text(json.dumps(dict(url=url, algorithm=algorithm, checksum=checksum)))
    temporary.replace(record)


def require_cached(path, url, algorithm, sums_url):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        raise MissingCachedImage(f'Reinstall requires cached image {path}; no VM was replaced.')
    if not path.is_file() or path.is_symlink():
        raise ValueError(f'Reinstall cache entry is not a regular file: {path}; no VM was replaced.')
    record = Path(str(path) + '.verified.json')
    if record.exists():
        saved = json.loads(record.read_text())
        if saved.get('url') != url or saved.get('algorithm') != algorithm:
            raise ValueError(f'Cached image source differs from configured source: {path}')
        expected = saved['checksum']
    else:
        # Older installations have no receipt. Verify against upstream without
        # downloading an image or changing the cache, even during a dry run.
        with urllib.request.urlopen(sums_url, timeout=60) as response:
            lines = response.read().decode().splitlines()
        filename = url.rsplit('/', 1)[-1]
        expected = next((parts[0].lower() for line in lines if len(parts := line.split()) == 2
                         and parts[1].lstrip('*').removeprefix('./') == filename), '')
    if not expected or digest(path, algorithm) != expected:
        raise ValueError(f'Cached image verification failed: {path}; refusing to download or replace a VM.')
    return path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['remember', 'require'])
    parser.add_argument('path')
    parser.add_argument('url')
    parser.add_argument('algorithm')
    parser.add_argument('value')
    args = parser.parse_args()
    try:
        if args.action == 'remember':
            remember(args.path, args.url, args.algorithm, args.value)
        else:
            print(require_cached(args.path, args.url, args.algorithm, args.value))
    except (OSError, ValueError, KeyError) as error:
        raise SystemExit(str(error))
