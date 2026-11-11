"""Multiple-feature structural candidates, kept separate from API certainty."""

from collections import Counter
from .model import Finding, Evidence, Material, merge_findings
from .ir import Expr
from .semantics import normalized_function, value_walk, rotate_pattern
from .forwarding import parameter_pointer
from .vector_patterns import vector_tools

TEA_DELTA = {0x9E3779B9, 0x61C88647, 0xC6EF3720}


def value_constants(function):
    values = []
    for e in function.expressions():
        if e.op == "num":
            values.append((e.value & 0xFFFFFFFF, e.ea))
    for i in function.instructions:
        for value in i.get("immediates", []):
            values.append((value & 0xFFFFFFFF, i["ea"]))
    return values


def rotates(expressions, instructions):
    r = set()
    locations = []
    for e in expressions:
        if e.op in ("rol", "ror") and len(e.args) > 1 and e.args[1].op == "num":
            n = e.args[1].value % 32
            r.add(n if e.op == "rol" else (32 - n) % 32)
            locations.append(e.ea)
        # Detect rotate expressed as (x<<n)|(x>>(32-n)), including addition.
        if e.op in ("or", "xor", "add") and len(e.args) == 2:
            a, b = e.args
            if a.op == "shr" and b.op == "shl":
                a, b = b, a
            if (
                a.op == "shl"
                and b.op == "shr"
                and len(a.args) == len(b.args) == 2
                and a.args[1].op == b.args[1].op == "num"
            ):
                if (
                    a.args[1].value + b.args[1].value == 32
                    and a.args[0].display() == b.args[0].display()
                ):
                    r.add(a.args[1].value)
                    locations.append(e.ea)
    for i in instructions:
        mnemonic = i.get("mnemonic", "").lower()
        if mnemonic in ("rol", "ror") and i.get("immediates"):
            n = i["immediates"][-1] % 32
            r.add(n if mnemonic == "rol" else (32 - n) % 32)
            locations.append(i["ea"])
    return r, locations


def structural_scan(function, lookup=None, reader=None):
    original = _scan_patterns(function, set(), reader)
    normalized, expanded = normalized_function(function, lookup)
    return merge_findings(original + _scan_patterns(normalized, expanded, reader))


def _scan_patterns(function, expanded_helpers, reader=None):
    expressions = list(function.expressions())
    ops = Counter(e.op for e in expressions)
    constants = value_constants(function)
    nums = {v for v, _ in constants}
    shifts = {
        e.args[1].value
        for e in expressions
        if e.op in ("shl", "shr", "sar") and len(e.args) > 1 and e.args[1].op == "num"
    }
    masks = {
        e.args[1].value
        for e in expressions
        if e.op == "and" and len(e.args) > 1 and e.args[1].op == "num"
    }
    # Fallback assembly features are less precise: only produce candidates.
    asm = Counter(i.get("mnemonic", "").lower() for i in function.instructions)
    for i in function.instructions:
        if i.get("mnemonic", "").lower() in (
            "shl",
            "sal",
            "shr",
            "sar",
            "lsl",
            "lsr",
        ) and i.get("immediates"):
            shifts.add(i["immediates"][-1])
    xor = ops["xor"] + ops["assign_xor"] + asm["xor"] + asm["eor"]
    add = ops["add"] + ops["assign_add"] + asm["add"]
    findings = []

    def report(
        algorithm, text, addresses, level="structural_match", materials=None, notes=None
    ):
        evidence = [
            Evidence(a, "structure", text) for a in sorted(set(addresses))[:12]
        ] or [Evidence(function.ea, "structure", text)]
        findings.append(
            Finding(
                function.ea,
                function.ea,
                algorithm,
                "unknown",
                level,
                "static",
                evidence,
                materials or [],
                notes=notes
                or [
                    "Structural match: mode and raw key are not implied by this function pattern."
                ],
            )
        )

    delta = [a for v, a in constants if v in TEA_DELTA]
    if delta and not expressions:
        report(
            "TEA-family",
            "Assembly delta/shift features; variant requires semantic analysis",
            delta,
            "candidate",
        )
    elif delta and {4, 5} <= shifts and xor >= 2 and add >= 2:
        if {2, 3, 4, 5} <= shifts and 3 in masks and ops["index"] + ops["load"] >= 3:
            report(
                "XXTEA",
                "delta + shifts 2/3/4/5 + key index mask 3 + word-array accesses",
                delta,
            )
        elif 11 in shifts and 3 in masks:
            report("XTEA", "delta + shifts 4/5 + sum>>11/key mask 3", delta)
        else:
            report("TEA", "delta + shifts 4/5 + add/XOR mixing", delta)
    elif delta:
        report(
            "TEA-family",
            "TEA-family delta alone; algorithm not established",
            delta,
            "candidate",
            notes=[
                "The same delta is used in TEA, XTEA, XXTEA and other code. No automatic key binding."
            ],
        )
    rotations, where = rotates(expressions, function.instructions)
    if {16, 12, 8, 7} <= rotations and xor >= 4 and add >= 4:
        report(
            "ChaCha-family",
            "ARX mixing with rotations 16/12/8/7",
            where,
            notes=[
                "Quarter-round structure does not distinguish ChaCha8/12/20 or nonce variant. Confirm full round schedule and state layout."
            ],
        )
    if {7, 9, 13, 18} <= rotations and xor >= 4 and add >= 4:
        report(
            "Salsa-family",
            "ARX mixing with rotations 7/9/13/18",
            where,
            notes=[
                "Quarter-round structure does not distinguish Salsa20/8, Salsa20/12 or full Salsa20. Confirm full round schedule and state layout."
            ],
        )
    byte_wrap = 255 in nums or any(e.op == "cast" and e.bits == 8 for e in expressions)
    memory_ops = ops["index"] + ops["load"]
    ksa = (
        256 in nums
        and byte_wrap
        and ops["mod"] + asm.get("div", 0) > 0
        and memory_ops >= 3
    )
    byte_stores = sum(
        e.op == "assign"
        and e.args
        and e.args[0].op in ("load", "index")
        and e.args[0].bits == 8
        for e in expressions
    )
    # Require the memory-to-memory half of a byte-state swap, plus an in-place XOR.
    swap_half = any(
        e.op == "assign"
        and len(e.args) == 2
        and all(a.op in ("load", "index") and a.bits == 8 for a in e.args)
        for e in expressions
    )
    xor_store = any(
        e.op == "assign_xor"
        and e.args
        and e.args[0].op in ("load", "index")
        and e.args[0].bits == 8
        for e in expressions
    )
    prga = (
        byte_wrap and memory_ops >= 7 and byte_stores >= 2 and swap_half and xor_store
    )
    if ksa or prga:
        report(
            "RC4",
            (
                "KSA-like 256-state/modulo-key-length"
                if ksa
                else "PRGA-like byte-state swaps and indexed keystream XOR"
            ),
            [a for n, a in constants if n in (256, 255)],
            "candidate",
            notes=[
                "KSA/PRGA-like features; inspect swap and state dependency to confirm RC4. A fragment alone does not prove full RC4."
            ],
        )
    # SIMD AES instructions provide evidence of an AES primitive, not its mode.
    aes_insns = [
        i["ea"]
        for i in function.instructions
        if i.get("mnemonic", "").lower()
        in (
            "aesenc",
            "aesenclast",
            "aesdec",
            "aesdeclast",
            "aeskeygenassist",
            "vaesenc",
            "vaesdec",
            "aese",
            "aesd",
        )
    ]
    if aes_insns:
        report("AES", "Hardware AES instruction", aes_insns, "instruction_match")
    # Scalar byte stores, including Hex-Rays compound assignment canonicalization.
    seen = set()
    vector_expand, vector_broadcast, vector_rotate = vector_tools(function, reader)

    def custom(op, constant, node, vector_bits=0):
        pair = (op, constant if constant is not None else node.display(), vector_bits)
        if pair in seen:
            return
        seen.add(pair)
        role = {
            "xor": "xor_constant",
            "add": "add_constant",
            "sub": "sub_constant",
            "rol": "rotate_left",
            "ror": "rotate_right",
        }[op]
        material = (
            Material(role, "recovered", scalar=constant, source="static")
            if constant is not None
            else Material(
                "operand", "unresolved", expression=node.display(), source="static"
            )
        )
        report(
            "Custom " + op.upper(),
            (
                "SIMD " + str(vector_bits) + "-bit byte lanes: "
                if vector_bits
                else "Byte load/store: "
            )
            + op
            + (" " + hex(constant) if constant is not None else " variable operand"),
            [node.ea],
            materials=[material],
            notes=[
                "Observed data transformation; direction and encryption intent remain unknown. Pointer/index arithmetic is excluded."
            ],
        )
        if vector_bits:
            findings[-1].metadata.update(vector_bits=vector_bits, lane_bits=8)

    for e in expressions:
        if len(e.args) != 2 or e.op not in (
            "assign",
            "assign_xor",
            "assign_add",
            "assign_sub",
        ):
            continue
        dest, rhs = e.args
        if dest.op not in ("index", "load", "member"):
            continue
        if dest.bits == 8:
            if e.op != "assign":
                rhs = Expr(e.op[7:], [dest, rhs], bits=8, ea=e.ea)
            if not any(
                n.op in ("index", "load", "member") and n.bits == 8 for n in rhs.walk()
            ):
                continue
            rot = rotate_pattern(rhs, 8)
            if rot:
                custom("rol", rot[1], rhs)
            for n in value_walk(rhs):
                if n.op in ("xor", "add", "sub", "rol", "ror") and len(n.args) == 2:
                    if rot and n is rhs:
                        continue
                    constant = next((x.value for x in n.args if x.op == "num"), None)
                    if n.op in ("rol", "ror") and n.bits not in (0, 8):
                        continue
                    custom(n.op, constant, n)
        elif dest.bits in (128, 256, 512):
            for n in value_walk(rhs):
                if n.op != "call" or not isinstance(n.value, dict):
                    continue
                name = n.value.get("name", "")
                actions = {
                    "_mm_xor_si128": "xor",
                    "_mm256_xor_si256": "xor",
                    "_mm512_xor_si512": "xor",
                    "_mm_add_epi8": "add",
                    "_mm256_add_epi8": "add",
                    "_mm512_add_epi8": "add",
                    "_mm_sub_epi8": "sub",
                    "_mm256_sub_epi8": "sub",
                    "_mm512_sub_epi8": "sub",
                }
                if name in actions:
                    constant = next(
                        (
                            v
                            for a in n.args
                            if (v := vector_broadcast(a, dest.bits)) is not None
                        ),
                        None,
                    )
                    custom(actions[name], constant, n, dest.bits)
                    if (
                        actions[name] == "add"
                        and constant is not None
                        and constant >= 128
                    ):
                        custom("sub", 256 - constant, n, dest.bits)
            rotation = vector_rotate(rhs, dest.bits)
            if rotation:
                custom("rol", rotation, rhs, dest.bits)
    # SIMD temporaries may carry the operation before the final memory store.
    vector_stores = any(
        e.op == "assign"
        and e.args
        and e.args[0].op in ("load", "index", "member")
        and e.args[0].bits in (128, 256, 512)
        for e in expressions
    )
    vector_loads = any(
        e.op == "call"
        and isinstance(e.value, dict)
        and e.value.get("name", "")
        in (
            "_mm_loadu_si128",
            "_mm_load_si128",
            "_mm256_loadu_si256",
            "_mm256_load_si256",
            "_mm512_loadu_si512",
        )
        for e in expressions
    )
    if vector_stores and vector_loads:
        for n in expressions:
            if n.op == "call" and isinstance(n.value, dict):
                name = n.value.get("name", "")
                op = (
                    "xor"
                    if name in ("_mm_xor_si128", "_mm256_xor_si256", "_mm512_xor_si512")
                    else (
                        "add"
                        if name in ("_mm_add_epi8", "_mm256_add_epi8")
                        else (
                            "sub"
                            if name in ("_mm_sub_epi8", "_mm256_sub_epi8")
                            else None
                        )
                    )
                )
                if op:
                    width = n.bits if n.bits in (128, 256, 512) else 128
                    constant = next(
                        (
                            v
                            for a in n.args
                            if (v := vector_broadcast(a, width)) is not None
                        ),
                        None,
                    )
                    custom(op, constant, n, width)
                    if op == "add" and constant is not None and constant >= 128:
                        custom("sub", 256 - constant, n, width)
    # A variant lacking a literal delta remains discoverable, with weak confidence.
    if (
        not any(f.algorithm in ("TEA", "XTEA", "XXTEA") for f in findings)
        and {4, 5} <= shifts
        and xor >= 2
        and add >= 2
    ):
        provisional = Finding(function.ea, function.ea, "TEA", confidence="candidate")
        if inferred_key_parameter(function, provisional):
            variant = "XTEA" if 11 in shifts and 3 in masks else "TEA"
            report(
                variant,
                "Four-word read-only key access and TEA-like word mixing; delta absent/dynamic",
                [function.ea],
                "candidate",
                notes=[
                    "Possible TEA variant. The delta/round schedule has not been established; verify manually."
                ],
            )
    # Dynamic rotations: report the state-mixing shape, do not substitute mutable
    # globals with their initial IDB values or claim the exact cipher/round count.
    if not any(f.algorithm == "ChaCha-family" for f in findings):
        variable_rotates = [
            e
            for e in expressions
            if e.op in ("rol", "ror")
            and len(e.args) == 2
            and e.args[1].op != "num"
            and e.bits == 32
        ]
        dynamic_pairs = [
            e
            for e in expressions
            if e.op in ("or", "xor")
            and len(e.args) == 2
            and {a.op for a in e.args} == {"shl", "shr"}
            and all(len(a.args) == 2 and a.args[1].op != "num" for a in e.args)
        ]
        if (
            (len(variable_rotates) >= 4 or len(dynamic_pairs) >= 4)
            and xor >= 4
            and add >= 4
            and memory_ops >= 8
        ):
            report(
                "ChaCha-family",
                "Word-state ARX mixing with four dynamic rotation sites",
                [e.ea for e in variable_rotates + dynamic_pairs],
                "candidate",
                notes=[
                    "Dynamic rotation/state shape only. Could be another ARX cipher; rotation values, layout and round count remain unknown."
                ],
            )
    # Include XOR-swap and widened state without requiring an exact byte swap.
    if (
        not any(f.algorithm == "RC4" for f in findings)
        and byte_wrap
        and memory_ops >= 7
    ):
        indexed_output = any(
            e.op == "assign_xor"
            and len(e.args) == 2
            and e.args[0].bits == 8
            and any(n.op in ("index", "load") for n in e.args[1].walk())
            for e in expressions
        )
        state_writes = sum(
            e.op.startswith("assign") and e.args and e.args[0].op in ("index", "load")
            for e in expressions
        )
        wide_swap = any(
            e.op == "assign"
            and len(e.args) == 2
            and all(a.op in ("index", "load") and a.bits in (16, 32) for a in e.args)
            for e in expressions
        )
        indirect_lookup = False
        for e in expressions:
            if e.op != "assign_xor" or len(e.args) != 2 or e.args[0].bits != 8:
                continue
            for n in e.args[1].walk():
                if n.op not in ("index", "load") or not n.args:
                    continue
                address = n.args[1] if n.op == "index" else n.args[0]
                if (
                    sum(
                        x.op in ("index", "load") for x in vector_expand(address).walk()
                    )
                    >= 2
                ):
                    indirect_lookup = True
        if (
            indexed_output
            and state_writes >= 3
            and (indirect_lookup or ops["assign_xor"] >= 4 or wide_swap)
        ):
            report(
                "RC4",
                "Indexed keystream XOR, wrapped indices and multiple state writes (swap variant)",
                [function.ea],
                "candidate",
                notes=[
                    "Permissive PRGA variant candidate, including XOR-swap/widened state. Confirm a 256-element permutation and index dependency; this does not imply a raw key."
                ],
            )
    word_destinations = {
        e.args[0].display()
        for e in expressions
        if e.op.startswith("assign")
        and e.args
        and e.args[0].op in ("load", "index", "member")
        and e.args[0].bits == 32
    }
    for f in findings:
        f.metadata["recognition"] = "observed_pattern_not_full_cipher_proof"
        if (
            f.algorithm in ("TEA", "XTEA", "XXTEA")
            and f.confidence == "structural_match"
            and not inferred_key_parameter(function, f)
        ):
            f.confidence = "candidate"
            f.notes.append(
                "No distinct four-word read-only key parameter established; a hash/ARX routine may share these features. Pattern retained as candidate."
            )
        if (
            f.algorithm in ("ChaCha-family", "Salsa-family")
            and f.confidence == "structural_match"
            and len(word_destinations) < 4
        ):
            f.confidence = "candidate"
            f.notes.append(
                "Fewer than four distinct word-state destinations; the feature combination may be unrelated ARX code. Pattern retained as candidate."
            )
        if expanded_helpers:
            f.metadata["expanded_helper_addresses"] = sorted(expanded_helpers)
            f.notes.append(
                "Small read-only return helpers were expanded for recognition; no IDB types/code were changed."
            )
        if f.algorithm == "RC4" and not ksa:
            f.notes.append(
                "Ambiguous PRGA features can also occur in AES key expansion; inspect state size and swaps."
            )
    return findings


def inferred_key_parameter(function, finding, lookup=None):
    """Only a conservative role candidate for TEA family, from four-word key access."""
    if lookup:
        function, _ = normalized_function(function, lookup)
    if finding.algorithm not in ("TEA", "XTEA", "XXTEA"):
        return None
    counts = Counter()
    modified = set()
    for e in function.expressions():
        if (
            (e.op == "assign" or e.op.startswith("assign_"))
            and e.args
            and e.args[0].op in ("index", "load", "member")
        ):
            modified.update(
                x.value
                for x in e.args[0].walk()
                if x.op == "var" and x.value in function.params
            )
    for e in function.expressions():
        if e.op == "load" and e.bits == 32 and e.args:
            mapped = parameter_pointer(e.args[0], function)
            if (
                mapped
                and mapped[1] in (0, 4, 8, 12)
                and function.params[mapped[0]] not in modified
            ):
                counts[function.params[mapped[0]]] += 1
            continue
        if e.op != "index" or len(e.args) < 2:
            continue
        base, index = e.args
        if base.op != "var" and index.op == "num":
            mapped = parameter_pointer(base, function)
            if (
                mapped
                and mapped[1] + index.value * e.scale in (0, 4, 8, 12)
                and e.bits == 32
                and function.params[mapped[0]] not in modified
            ):
                counts[function.params[mapped[0]]] += 1
            continue
        if (
            base.op != "var"
            or base.value not in function.params
            or base.value in modified
            or e.bits != 32
        ):
            continue
        variable_mask = any(
            n.op == "and" and any(a.op == "num" and a.value == 3 for a in n.args)
            for n in index.walk()
        )
        if variable_mask or index.op == "num" and index.value in (0, 1, 2, 3):
            counts[base.value] += 1
    if not counts:
        return None
    winner, count = counts.most_common(1)[0]
    minimum = 3 if finding.algorithm == "TEA" else 2
    if count < minimum or len(counts) > 1 and counts.most_common(2)[1][1] >= count:
        return None
    return dict(
        arg=function.params.index(winner),
        length=16,
        role="key",
        kind="bytes",
        candidate=True,
    )
