"""Host-only retrieval of four pinned official Ubuntu kernel packages."""
import concurrent.futures
import hashlib
import json
import urllib.request
from pathlib import Path

BASE='https://archive.ubuntu.com/ubuntu/pool/main/l/linux-hwe-6.5/'
VERSION='6.5.0-45.45~22.04.1'
NAMES=[f'linux-image-unsigned-6.5.0-45-generic_{VERSION}_amd64.deb',
       f'linux-modules-6.5.0-45-generic_{VERSION}_amd64.deb',
       f'linux-headers-6.5.0-45-generic_{VERSION}_amd64.deb',
       f'linux-hwe-6.5-headers-6.5.0-45_{VERSION}_all.deb']
OUTPUT=Path(__file__).resolve().parent/'downloads'


def fetch(name):
    path=OUTPUT/name
    if path.exists(): raise FileExistsError(path)
    url=BASE+name
    with urllib.request.urlopen(url,timeout=60) as response:
        payload=response.read()
    with path.open('xb') as stream: stream.write(payload)
    record={'filename':name,'url':url,'sha256':hashlib.sha256(payload).hexdigest(),'bytes':len(payload)}
    print(json.dumps(record),flush=True)
    return record


if __name__=='__main__':
    OUTPUT.mkdir(exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        records=list(pool.map(fetch,NAMES))
    with (OUTPUT/'kernel_packages.json').open('x') as stream:
        json.dump({'kernel':'6.5.0-45-generic','packages':records,
                   'trust':'official HTTPS retrieval; saved SHA-256, not a signed-index validation'},stream,indent=2)
