"""Streaming multiset fingerprints and IBLTs for directory reconciliation.

The implementation deliberately uses only 64-bit integer operations that can
also be implemented in eBPF.  It is not a cryptographic authentication
primitive.  Per-campaign random seeds make accidental or precomputed
collisions unlikely, while an exact oracle remains mandatory during method
development and validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence


MASK64 = (1 << 64) - 1
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
POS3_SALT = 0xD6E8FEB86659FD93
CHECK_SALT = 0xA0761D6478BD642F
FP2_SALT = 0xE7037ED1A0B428DB


def mix64(value: int) -> int:
    """SplitMix64 finalizer, expressed with eBPF-compatible operations."""

    value &= MASK64
    value ^= value >> 30
    value = (value * 0xBF58476D1CE4E5B9) & MASK64
    value ^= value >> 27
    value = (value * 0x94D049BB133111EB) & MASK64
    value ^= value >> 31
    return value & MASK64


@dataclass(frozen=True, slots=True)
class EntryToken:
    """Bounded identity retained by the sketch, not the raw file name."""

    key_hash: int
    inode: int
    d_type: int

    def normalized(self) -> "EntryToken":
        return EntryToken(
            self.key_hash & MASK64,
            self.inode & MASK64,
            self.d_type & 0xFF,
        )


def token_for_entry(
    name: bytes | str,
    inode: int,
    d_type: int,
    seed1: int,
    seed2: int,
) -> EntryToken:
    """Hash the fields available at both filldir64 and linux_dirent64."""

    raw = name.encode("utf-8", "surrogateescape") if isinstance(name, str) else name
    value = (FNV_OFFSET ^ seed1) & MASK64
    for byte in raw:
        value ^= byte
        value = (value * FNV_PRIME) & MASK64
    value ^= mix64((inode & MASK64) ^ seed2)
    value ^= mix64((d_type & 0xFF) ^ ((len(raw) & 0xFFFF) << 8) ^ seed1)
    return EntryToken(mix64(value), inode & MASK64, d_type & 0xFF)


def token_check(token: EntryToken, seed1: int, seed2: int) -> int:
    token = token.normalized()
    value = token.key_hash ^ mix64(token.inode ^ seed1)
    value ^= ((token.d_type & 0xFF) << 56) ^ seed2 ^ CHECK_SALT
    return mix64(value)


@dataclass(slots=True)
class MultisetFingerprint:
    """Order-independent fixed-size summary that retains multiplicity."""

    count: int = 0
    sum1: int = 0
    sum2: int = 0

    def add(self, token: EntryToken, sign: int = 1) -> None:
        if sign not in (-1, 1):
            raise ValueError("sign must be -1 or 1")
        token = token.normalized()
        self.count += sign
        self.sum1 = (self.sum1 + sign * token.key_hash) & MASK64
        second = mix64(token.key_hash ^ token.inode ^ FP2_SALT)
        second ^= mix64(token.d_type)
        self.sum2 = (self.sum2 + sign * second) & MASK64

    @classmethod
    def from_tokens(cls, tokens: Iterable[EntryToken]) -> "MultisetFingerprint":
        result = cls()
        for token in tokens:
            result.add(token)
        return result

    def as_tuple(self) -> tuple[int, int, int]:
        return self.count, self.sum1, self.sum2


@dataclass(slots=True)
class IBLTCell:
    count: int = 0
    key_xor: int = 0
    inode_xor: int = 0
    type_xor: int = 0
    check_xor: int = 0

    def is_empty(self) -> bool:
        return (
            self.count == 0
            and self.key_xor == 0
            and self.inode_xor == 0
            and self.type_xor == 0
            and self.check_xor == 0
        )

    def copy(self) -> "IBLTCell":
        return IBLTCell(
            self.count,
            self.key_xor,
            self.inode_xor,
            self.type_xor,
            self.check_xor,
        )


@dataclass(frozen=True, slots=True)
class DecodeResult:
    success: bool
    upstream_only: tuple[EntryToken, ...]
    downstream_only: tuple[EntryToken, ...]
    residual_cells: int


class IBLT:
    """Three-hash invertible Bloom lookup table for unique directory tokens."""

    HASH_COUNT = 3

    def __init__(self, cell_count: int, seed1: int, seed2: int):
        if cell_count < 4 or cell_count & (cell_count - 1):
            raise ValueError("cell_count must be a power of two and at least 4")
        self.cell_count = cell_count
        self.seed1 = seed1 & MASK64
        self.seed2 = seed2 & MASK64
        self.cells = [IBLTCell() for _ in range(cell_count)]

    def _positions(self, key_hash: int) -> tuple[int, int, int]:
        mask = self.cell_count - 1
        first = mix64(key_hash ^ self.seed1) & mask
        second = mix64(key_hash ^ self.seed2) & mask
        if second == first:
            second = (second + 1) & mask
        third = mix64(key_hash ^ self.seed1 ^ self.seed2 ^ POS3_SALT) & mask
        while third == first or third == second:
            third = (third + 1) & mask
        return first, second, third

    def add(self, token: EntryToken, sign: int = 1) -> None:
        if sign not in (-1, 1):
            raise ValueError("sign must be -1 or 1")
        token = token.normalized()
        check = token_check(token, self.seed1, self.seed2)
        for position in self._positions(token.key_hash):
            cell = self.cells[position]
            cell.count += sign
            cell.key_xor ^= token.key_hash
            cell.inode_xor ^= token.inode
            cell.type_xor ^= token.d_type
            cell.check_xor ^= check

    @classmethod
    def from_tokens(
        cls,
        tokens: Iterable[EntryToken],
        cell_count: int,
        seed1: int,
        seed2: int,
    ) -> "IBLT":
        result = cls(cell_count, seed1, seed2)
        for token in tokens:
            result.add(token)
        return result

    def subtract(self, other: "IBLT") -> "IBLT":
        if (
            self.cell_count != other.cell_count
            or self.seed1 != other.seed1
            or self.seed2 != other.seed2
        ):
            raise ValueError("IBLT parameters differ")
        result = IBLT(self.cell_count, self.seed1, self.seed2)
        for index, (left, right) in enumerate(zip(self.cells, other.cells)):
            result.cells[index] = IBLTCell(
                count=left.count - right.count,
                key_xor=left.key_xor ^ right.key_xor,
                inode_xor=left.inode_xor ^ right.inode_xor,
                type_xor=left.type_xor ^ right.type_xor,
                check_xor=left.check_xor ^ right.check_xor,
            )
        return result

    def _pure_token(self, cell: IBLTCell) -> EntryToken | None:
        if abs(cell.count) != 1 or cell.type_xor > 0xFF:
            return None
        token = EntryToken(cell.key_xor, cell.inode_xor, cell.type_xor)
        if token_check(token, self.seed1, self.seed2) != cell.check_xor:
            return None
        return token

    def decode(self) -> DecodeResult:
        work = [cell.copy() for cell in self.cells]
        queue = [
            index for index, cell in enumerate(work)
            if self._pure_token(cell) is not None
        ]
        queued = set(queue)
        upstream: list[EntryToken] = []
        downstream: list[EntryToken] = []
        cursor = 0
        while cursor < len(queue):
            index = queue[cursor]
            cursor += 1
            queued.discard(index)
            cell = work[index]
            token = self._pure_token(cell)
            if token is None:
                continue
            sign = 1 if cell.count == 1 else -1
            (upstream if sign == 1 else downstream).append(token)
            check = token_check(token, self.seed1, self.seed2)
            for position in self._positions(token.key_hash):
                target = work[position]
                target.count -= sign
                target.key_xor ^= token.key_hash
                target.inode_xor ^= token.inode
                target.type_xor ^= token.d_type
                target.check_xor ^= check
                if (
                    position not in queued
                    and self._pure_token(target) is not None
                ):
                    queue.append(position)
                    queued.add(position)
        residual = sum(not cell.is_empty() for cell in work)
        key = lambda item: (item.key_hash, item.inode, item.d_type)
        return DecodeResult(
            success=residual == 0,
            upstream_only=tuple(sorted(upstream, key=key)),
            downstream_only=tuple(sorted(downstream, key=key)),
            residual_cells=residual,
        )

    def to_rows(self) -> list[tuple[int, int, int, int, int]]:
        return [
            (
                cell.count,
                cell.key_xor,
                cell.inode_xor,
                cell.type_xor,
                cell.check_xor,
            )
            for cell in self.cells
        ]

    @classmethod
    def from_rows(
        cls,
        rows: Sequence[Sequence[int]],
        seed1: int,
        seed2: int,
    ) -> "IBLT":
        result = cls(len(rows), seed1, seed2)
        result.cells = [IBLTCell(*map(int, row)) for row in rows]
        return result


def recommended_cell_count(expected_difference: int, factor: float = 2.0) -> int:
    """Return a conservative power-of-two table size for a pilot design."""

    if expected_difference < 0:
        raise ValueError("expected_difference must be non-negative")
    target = max(4, int(expected_difference * factor + 0.999999))
    return 1 << (target - 1).bit_length()
