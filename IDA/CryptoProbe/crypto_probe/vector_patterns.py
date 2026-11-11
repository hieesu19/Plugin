"""Bounded use/def expansion for SIMD byte transforms and byte rotations."""

from collections import defaultdict
from dataclasses import replace
from .memory import PartialMemory, Pointer
from .simd import evaluate


def vector_tools(function, reader=None):
    definitions = defaultdict(list)
    for e in function.expressions():
        if e.op == "assign" and len(e.args) == 2 and e.args[0].op == "var":
            definitions[e.args[0].value].append(e.args[1])

    def expand(e, path=(), depth=0, budget=None):
        if budget is None:
            budget = [8000]
        budget[0] -= 1
        if depth > 18 or budget[0] <= 0:
            return e
        if e.op == "var" and e.value not in path and len(definitions[e.value]) == 1:
            return expand(definitions[e.value][0], path + (e.value,), depth + 1, budget)
        return replace(e, args=[expand(a, path, depth + 1, budget) for a in e.args])

    memory = PartialMemory(reader)

    def known(e, depth=0):
        if depth > 20:
            return None
        if e.op == "num":
            return e.value
        if e.op == "cast" and e.args:
            v = known(e.args[0], depth + 1)
            return (
                v & ((1 << e.bits) - 1)
                if isinstance(v, int) and 0 < e.bits <= 512
                else v
            )
        if (
            e.op == "global"
            and e.scale == 0
            and isinstance(e.value, int)
            and e.bits in (8, 16, 32, 64, 128, 256, 512)
        ):
            v = memory.load(Pointer("image", e.value), e.bits // 8)
            return v if isinstance(v, int) else None
        if e.op == "call" and isinstance(e.value, dict):
            values = [known(a, depth + 1) for a in e.args]
            if not all(isinstance(v, int) for v in values):
                return None
            name = e.value.get("name", "")
            # Loads from caller memory are unknown; arithmetic-only exact models.
            if "load" in name or "store" in name:
                return None
            v = evaluate(name, values, memory)
            return v if isinstance(v, int) else None
        return None

    def broadcast(e, width):
        v = known(expand(e))
        if v is None:
            return None
        raw = (v & ((1 << width) - 1)).to_bytes(width // 8, "little")
        return raw[0] if len(set(raw)) == 1 else None

    def left(e):
        if (
            e.op == "call"
            and isinstance(e.value, dict)
            and e.value.get("name", "") in ("_mm_add_epi8", "_mm256_add_epi8")
            and len(e.args) == 2
            and e.args[0].display() == e.args[1].display()
        ):
            x, n = left(e.args[0])
            return x, n + 1
        return e, 0

    def right(e, width):
        if (
            e.op != "call"
            or not isinstance(e.value, dict)
            or e.value.get("name", "") not in ("_mm_and_si128", "_mm256_and_si256")
            or len(e.args) != 2
        ):
            return None
        for a, b in (e.args, e.args[::-1]):
            if (
                a.op == "call"
                and isinstance(a.value, dict)
                and a.value.get("name", "") in ("_mm_srli_epi16", "_mm256_srli_epi16")
                and len(a.args) == 2
            ):
                n = known(a.args[1])
                mask = broadcast(b, width)
                if isinstance(n, int) and 0 < n < 8 and mask == (1 << (8 - n)) - 1:
                    return a.args[0], n
        return None

    def rotation(e, width):
        e = expand(e)
        if (
            e.op != "call"
            or not isinstance(e.value, dict)
            or e.value.get("name", "")
            not in (
                "_mm_or_si128",
                "_mm256_or_si256",
                "_mm_xor_si128",
                "_mm256_xor_si256",
            )
            or len(e.args) != 2
        ):
            return None
        for a, b in (e.args, e.args[::-1]):
            src, n = left(a)
            r = right(b, width)
            if n and r and n + r[1] == 8 and src.display() == r[0].display():
                return n
        return None

    return expand, broadcast, rotation
