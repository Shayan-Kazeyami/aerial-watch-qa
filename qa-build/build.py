"""Build an isolated QA Pages payload from the restored candidate, offline."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile

ID = r'[0-9a-f]{64}'
PATH = re.compile(rf'preview-b/releases/{ID}/[a-zA-Z0-9_.+-]+(?:/[a-zA-Z0-9_.+-]+)*\Z')
ALLOW_SHA = 'dd91cab2fa065696cac00adf0e71c48025a7576a6e17eb5684c6fb3d51ebf6d7'

def require(condition, msg):
    if not condition:
        raise ValueError(msg)

def read_rows():
    raw = Path(__file__).with_name('ALLOWLIST.tsv').read_bytes()
    require(hashlib.sha256(raw).hexdigest() == ALLOW_SHA, 'allowlist integrity mismatch')
    rows = {}
    for line in raw.decode('ascii').splitlines():
        sha, size, name = line.split('\t')
        require(re.fullmatch(ID, sha) and size.isdecimal(), f'invalid row: {name}')
        require(PATH.fullmatch(name) and not {'.','..'} & set(name.split('/')), f'unsafe path: {name}')
        require(name.casefold() not in rows, f'repeated case-folded name: {name}')
        rows[name.casefold()] = (name, sha, int(size))
    require(len(rows) == 293 and sum(x[2] for x in rows.values()) == 276197756, 'unexpected inventory')
    return rows.values()

def main():
    ap = argparse.ArgumentParser(); ap.add_argument('source', type=Path); ap.add_argument('output', type=Path)
    opts = ap.parse_args()
    require(not opts.source.is_symlink() and opts.source.is_dir(), 'invalid source root')
    src = opts.source.resolve(strict=True)
    destination = opts.output.absolute()
    parent = destination.parent.resolve(strict=True)
    destination = parent / destination.name
    require(parent != src and src not in parent.parents and destination not in src.parents, 'keep output outside source')
    require(not destination.exists() and not destination.is_symlink(), 'output already exists')
    rows = read_rows()
    with tempfile.TemporaryDirectory(prefix='.watch-qa-build-', dir=parent) as temp:
        stage = Path(temp)/'payload'
        stage.mkdir()
        for name, sha, size in rows:
            rel = PurePosixPath(name)
            source = src / rel
            require(source.resolve(strict=True) == source and source.is_file(), f'not a plain source file: {name}')
            dest = stage / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            digest = hashlib.sha256(); bytes_read = 0
            with source.open('rb') as f, dest.open('xb') as o:
                while chunk := f.read(1024 * 1024):
                    digest.update(chunk); bytes_read += len(chunk); o.write(chunk)
            require(bytes_read == size and digest.hexdigest() == sha, f'candidate bytes mismatch: {name}')
        (stage/'.nojekyll').touch(exist_ok=False)
        # Publish locally via a reserved fresh directory, never overwrite an existing target.
        destination.mkdir(exist_ok=False)
        try:
            for child in stage.iterdir():
                child.rename(destination/child.name)
        except BaseException:
            shutil.rmtree(destination)
            raise
    print(f'Built {len(rows)} pinned files + .nojekyll: {destination}')
if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as e:
        raise SystemExit(f'REJECT {e}')
