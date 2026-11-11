"""Partial byte memory: unknown bytes never silently become zero."""

from dataclasses import dataclass
import copy


@dataclass(frozen=True)
class Pointer:
    space: str
    base: object
    offset: int = 0

    def add(self, n):
        return Pointer(self.space, self.base, self.offset + int(n))

    def address(self):
        return int(self.base) + self.offset if self.space == "image" else None

    def label(self):
        return "%s:%s%+d" % (self.space, str(self.base), self.offset)


@dataclass(frozen=True)
class Tagged:
    kind: str
    value: object


@dataclass(frozen=True)
class Affine:
    space: str
    base: object
    coefficient: int
    offset: int
    bits: int


@dataclass(frozen=True)
class Residue:
    value: int
    bits: int


@dataclass(frozen=True)
class Unknown:
    reason: str = "unknown"


UNKNOWN = Unknown()


class PartialMemory:
    def __init__(self, reader=None, endian="little"):
        self.reader = reader
        self.endian = endian
        self.cells = {}
        self.objects = {}
        self.tainted = set()

    def clone(self):
        m = PartialMemory(self.reader, self.endian)
        m.cells = copy.deepcopy(self.cells)
        m.objects = copy.deepcopy(self.objects)
        m.tainted = set(self.tainted)
        return m

    @staticmethod
    def key(p):
        return (
            (p.space, 0, p.address())
            if p.space == "image"
            else (p.space, p.base, p.offset)
        )

    def write(self, p, data):
        if not isinstance(p, Pointer):
            return
        for off, b in enumerate(data):
            self.cells[self.key(p.add(off))] = b
        for key in list(self.objects):
            space, base, start, size = key
            ps, pb, po = self.key(p)
            if (
                space == ps
                and base == pb
                and start < po + len(data)
                and start + size > po
            ):
                del self.objects[key]

    def store(self, p, value, size):
        if not isinstance(p, Pointer) or size < 1 or size > 64:
            return
        if isinstance(value, int):
            self.write(
                p, list((value & ((1 << (size * 8)) - 1)).to_bytes(size, self.endian))
            )
        else:
            self.write(p, [None] * size)
            if isinstance(value, (Pointer, Tagged, Affine, Residue)):
                self.objects[(*self.key(p), size)] = value

    def bytes(self, p, size):
        if not isinstance(p, Pointer) or size < 0 or size > 1048576:
            return None
        raw = None
        address = p.address()
        if address is not None and self.reader and self.key(p)[:2] not in self.tainted:
            try:
                raw = self.reader(address, size)
            except Exception:
                raw = None
        result = []
        for off in range(size):
            key = self.key(p.add(off))
            result.append(
                self.cells[key]
                if key in self.cells
                else raw[off] if raw is not None and off < len(raw) else None
            )
        return result

    def load(self, p, size):
        if not isinstance(p, Pointer):
            return UNKNOWN
        key = (*self.key(p), size)
        if key in self.objects:
            return self.objects[key]
        data = self.bytes(p, size)
        return (
            int.from_bytes(bytes(data), self.endian)
            if data is not None and all(b is not None for b in data)
            else Unknown("uninitialized/missing memory")
        )

    def invalidate(self, p, size=None):
        if not isinstance(p, Pointer):
            return
        if size is not None and 0 <= size <= 1048576:
            self.write(p, [None] * size)
            return
        basekey = self.key(p)[:2]
        self.tainted.add(basekey)
        for k in list(self.cells):
            if k[:2] == basekey:
                self.cells[k] = None
        for k in list(self.objects):
            if k[:2] == basekey:
                del self.objects[k]

    def release_frame(self, frame):
        """Forget a finished callee's local slots, preserving caller/heap data."""

        def owned(space, base):
            return (
                space == "stack"
                and base == frame
                or space == "local"
                and isinstance(base, tuple)
                and base[0] == frame
            )

        for key in list(self.cells):
            if owned(key[0], key[1]):
                del self.cells[key]
        for key in list(self.objects):
            if owned(key[0], key[1]):
                del self.objects[key]
        self.tainted = {key for key in self.tainted if not owned(*key)}

    def merge(self, other):
        self.tainted |= other.tainted
        for key in set(self.cells) | set(other.cells):
            a = self.cells.get(key)
            b = other.cells.get(key)
            self.cells[key] = a if a == b else None
        for key in list(self.objects):
            if self.objects[key] != other.objects.get(key):
                del self.objects[key]
