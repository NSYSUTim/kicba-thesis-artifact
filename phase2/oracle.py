"""Independent expected identities for the controlled output transformations."""

from collections import Counter
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from kicba.reconciliation import token_for_entry

SEED1, SEED2 = 0x0123456789ABCDEF, 0xF0E1D2C3B4A59687
SUBJECT = b'phase2_subject'
INSERTED = b'phase2_inserted'
INSERT_INODE = 0x7fff000000000123
ACTIONS = ('normal', 'reorder', 'insert', 'grow', 'shrink', 'inode', 'type', 'remove')


def identities(rows):
    values = []
    for row in rows:
        name = bytes.fromhex(row['name_hex'])
        inode, kind = row['inode'], row['d_type']
        if (not name or b'\0' in name or b'/' in name or len(name) > 255
                or type(inode) is not int or not 0 <= inode < 2**64
                or type(kind) is not int or not 0 <= kind < 256):
            raise ValueError('invalid exact identity')
        values.append((name, inode, kind))
    return sorted(values)


def transform(rows, action):
    if action not in ACTIONS:
        raise ValueError('unknown action')
    identities(rows)
    result = [dict(row) for row in rows]
    if action == 'normal':
        return result
    if action == 'reorder':
        return result[::-1]
    positions = [i for i, row in enumerate(rows) if bytes.fromhex(row['name_hex']) == SUBJECT]
    if len(positions) != 1:
        raise ValueError('requires exactly one subject')
    index = positions[0]
    if action == 'insert':
        result.append({'name_hex': INSERTED.hex(), 'inode': INSERT_INODE, 'd_type': 8})
    elif action == 'remove':
        del result[index]
    elif action == 'inode':
        result[index]['inode'] ^= 1 << 62
    elif action == 'type':
        result[index]['d_type'] = 4
    elif action in ('grow', 'shrink'):
        result[index]['name_hex'] = (b'phase2_subject_much_longer_name' if action == 'grow' else b'p2x').hex()
    return result


def token_rows(rows):
    result = []
    for name, inode, kind in identities(rows):
        token = token_for_entry(name, inode, kind, SEED1, SEED2)
        result.append((token.key_hash, token.inode, token.d_type))
    return result


def difference(upstream, downstream):
    up, down = Counter(token_rows(upstream)), Counter(token_rows(downstream))
    return (sorted([list(t) for t in (up - down).elements()]),
            sorted([list(t) for t in (down - up).elements()]))
