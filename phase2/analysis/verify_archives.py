"""Read-only checksum/source verification; optional safe unpack of data archives."""
import argparse
import hashlib
import json
import tarfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[2]
PHASE=ROOT/'phase2'


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--unpack',action='store_true');args=parser.parse_args()
    directory=PHASE/'evidence/downloads';verified={}
    for metadata in sorted(directory.glob('*.tar.gz.sha256.json')):
        record=json.loads(metadata.read_text(encoding='utf-8-sig'))
        path=directory/record['filename']
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if digest!=record['sha256']:raise RuntimeError('archive changed '+path.name)
        verified[path.name]=digest
        if args.unpack and not path.name.startswith('frozen_sources_'):
            with tarfile.open(path) as bundle:
                for member in bundle:
                    if not member.isfile():continue
                    name=Path(member.name)
                    if name.is_absolute() or '..' in name.parts or name.parts[0]!='phase2':raise RuntimeError('unsafe member')
                    target=ROOT/name
                    payload=bundle.extractfile(member).read()
                    if target.exists():
                        if hashlib.sha256(target.read_bytes()).hexdigest()!=hashlib.sha256(payload).hexdigest():
                            raise RuntimeError('conflicting existing member '+member.name)
                    else:
                        target.parent.mkdir(parents=True,exist_ok=True)
                        with target.open('xb') as stream:stream.write(payload)
    source_counts={}
    for tag in ('kernel65','kernel68'):
        lock=PHASE/'locks'/(tag+'.json')
        if not lock.exists():continue
        lock=json.loads(lock.read_text())
        with tarfile.open(directory/f'frozen_sources_{tag}.tar.gz') as bundle:
            for name,digest in lock['source_sha256'].items():
                if hashlib.sha256(bundle.extractfile(name).read()).hexdigest()!=digest:
                    raise RuntimeError('source bytes changed '+tag+'/'+name)
        source_counts[tag]=len(lock['source_sha256'])
    print(json.dumps({'archives_verified':len(verified),'archive_sha256':verified,
                      'frozen_sources_verified':source_counts},indent=2))
