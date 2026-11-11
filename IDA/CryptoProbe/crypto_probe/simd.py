"""Exact, bounded integer models for common SSE/AVX initialization intrinsics.

Only concrete values are calculated. Unknown lanes never become zero. Return
None for an unsupported helper so the caller's existing invalidation applies.
"""

from .memory import Pointer, UNKNOWN


def evaluate(name, values, memory):
    name = "_" + name.lstrip("_")
    prefix = (
        "_mm512_"
        if name.startswith("_mm512_")
        else (
            "_mm256_"
            if name.startswith("_mm256_")
            else "_mm_" if name.startswith("_mm_") else None
        )
    )
    if prefix is None:
        return None
    width = 512 if prefix == "_mm512_" else 256 if prefix == "_mm256_" else 128
    op = name[len(prefix) :]
    mask = (1 << width) - 1

    def ints(n):
        return len(values) == n and all(isinstance(v, int) for v in values)

    if op in (
        "loadu_si128",
        "load_si128",
        "loadu_si256",
        "load_si256",
        "loadu_si512",
        "load_si512",
    ):
        return (
            memory.load(values[0], width // 8)
            if len(values) == 1 and isinstance(values[0], Pointer)
            else UNKNOWN
        )
    if op in (
        "storeu_si128",
        "store_si128",
        "storeu_si256",
        "store_si256",
        "storeu_si512",
        "store_si512",
    ):
        if len(values) == 2:
            memory.store(values[0], values[1], width // 8)
        return UNKNOWN
    if op in ("setzero_si128", "setzero_si256", "setzero_si512"):
        return 0
    if op in ("cvtsi32_si128", "cvtsi64_si128"):
        return (
            values[0] & ((1 << (32 if op == "cvtsi32_si128" else 64)) - 1)
            if ints(1)
            else UNKNOWN
        )
    if op == "shuffle_epi32":
        if not ints(2):
            return UNKNOWN
        v, control = values
        return sum(
            (
                (v >> (lane // 4 * 128 + ((control >> (2 * (lane % 4))) & 3) * 32))
                & 0xFFFFFFFF
            )
            << (lane * 32)
            for lane in range(width // 32)
        )
    if op in (
        "xor_si128",
        "xor_si256",
        "xor_si512",
        "and_si128",
        "and_si256",
        "and_si512",
        "or_si128",
        "or_si256",
        "or_si512",
    ):
        if not ints(2):
            return UNKNOWN
        a, b = values
        return (
            (a ^ b)
            if op.startswith("xor")
            else (a & b) if op.startswith("and") else (a | b)
        ) & mask
    for bits in (8, 16, 32, 64):
        lane_mask = (1 << bits) - 1
        if op in ("unpacklo_epi" + str(bits), "unpackhi_epi" + str(bits)):
            if not ints(2):
                return UNKNOWN
            a, b = values
            out = 0
            half_lanes = 64 // bits
            first = half_lanes if op.startswith("unpackhi") else 0
            for block in range(0, width, 128):
                for lane in range(half_lanes):
                    at = block + (first + lane) * bits
                    out |= ((a >> at) & lane_mask) << (block + 2 * lane * bits)
                    out |= ((b >> at) & lane_mask) << (block + (2 * lane + 1) * bits)
            return out
        if op == "set1_epi" + str(bits):
            return (
                sum((values[0] & lane_mask) << i for i in range(0, width, bits))
                if ints(1)
                else UNKNOWN
            )
        if op in (
            "add_epi" + str(bits),
            "sub_epi" + str(bits),
            "slli_epi" + str(bits),
            "srli_epi" + str(bits),
        ):
            if not ints(2):
                return UNKNOWN
            a, b = values
            out = 0
            for i in range(0, width, bits):
                av = (a >> i) & lane_mask
                bv = (b >> i) & lane_mask
                if op.startswith("add"):
                    r = av + bv
                elif op.startswith("sub"):
                    r = av - bv
                elif b >= bits:
                    r = 0
                elif b < 0:
                    return UNKNOWN
                else:
                    r = av << b if op.startswith("slli") else av >> b
                out |= (r & lane_mask) << i
            return out
    return None
