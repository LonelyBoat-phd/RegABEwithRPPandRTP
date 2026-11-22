#!/usr/bin/env python3
"""Check a source release against SHA256SUMS; --write refreshes the manifest."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import sys

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = 'SHA256SUMS'
# 'runbook' and 'logs' are operator tooling and run output: they are meant to be
# adapted per machine and must not make the source manifest stale.
EXCLUDED = {'.git', '.venv', 'venv', '__pycache__', 'build', 'dist',
            'results', 'logs', 'runbook',
            '.pytest_cache', '.mypy_cache', '.ruff_cache'}


def source_files(root):
    for path in sorted(root.rglob('*')):
        relative = path.relative_to(root)
        if any(part in EXCLUDED or part.endswith('.egg-info') for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError('release symlink: ' + relative.as_posix())
        if not path.is_file() or relative.as_posix() == MANIFEST:
            continue
        if path.suffix in {'.so', '.pyc', '.pyo', '.o', '.a'}:
            continue
        if relative.as_posix() == 'native/build-info.json':
            continue
        yield relative.as_posix(), path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(root):
    expected = {}
    for line in (root / MANIFEST).read_text(encoding='utf-8').splitlines():
        checksum, relative = line.split('  ', 1)
        name = PurePosixPath(relative)
        if (len(checksum) != 64 or any(c not in '0123456789abcdef' for c in checksum)
                or not name.parts or name.is_absolute() or '..' in name.parts
                or name.as_posix() != relative or '\\' in relative
                or relative in expected):
            raise ValueError('invalid manifest entry')
        expected[relative] = checksum
    if not expected:
        raise ValueError('empty manifest')
    actual = {name: digest(path) for name, path in source_files(root)}
    missing = sorted(expected.keys() - actual.keys())
    extra = sorted(actual.keys() - expected.keys())
    changed = sorted(name for name in expected.keys() & actual.keys()
                     if expected[name] != actual[name])
    if missing or extra or changed:
        raise ValueError(f'source integrity mismatch: missing={missing}, added={extra}, changed={changed}')
    return len(actual)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='refresh after intentional source changes')
    args = parser.parse_args()
    try:
        if args.write:
            rows = [(name, digest(path)) for name, path in source_files(ROOT)]
            (ROOT / MANIFEST).write_text(''.join(f'{value}  {name}\n' for name, value in rows), encoding='utf-8')
        count = check(ROOT)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(f'Source integrity verified: {count} files.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
