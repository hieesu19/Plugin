"""Bounded structured partial evaluation; unknown branches are merged conservatively."""

import copy
import itertools
from .ir import Expr
from .memory import Pointer, Tagged, Unknown, UNKNOWN, PartialMemory, Affine, Residue
from .materials import ApiDecoder, Contexts, context_key, read_string, read_bytes
from .simd import evaluate as evaluate_simd
from .apis import normalize_name, cipher_descriptor, parse_cipher_string


class BudgetExceeded(Exception):
    pass


class StopPath(Exception):
    pass


class BreakLoop(Exception):
    pass


class Interpreter:
    def __init__(
        self,
        function,
        catalog,
        reader=None,
        endian="little",
        pointer_size=8,
        lookup=None,
        depth=0,
        max_steps=12000,
        frame=None,
        frame_ids=None,
        call_chain=(),
    ):
        self.function = function
        self.catalog = catalog
        self.memory = PartialMemory(reader, endian)
        self.env = {}
        self.contexts = Contexts()
        self.findings = []
        self.calls = []
        self.diagnostics = []
        self.pointer_size = pointer_size
        self.lookup = lookup
        self.depth = depth
        self.steps = 0
        self.max_steps = max_steps
        self.conditional = 0
        self.return_value = UNKNOWN
        self.return_paths = []
        self.value_context = 0
        self.frame = function.ea if frame is None else frame
        self.frame_ids = frame_ids if frame_ids is not None else itertools.count(1)
        self.call_chain = call_chain
        for name, info in function.varinfo.items():
            if info.get("array"):
                self.env[name] = self.address(Expr("var", value=name))
        for n, name in enumerate(function.params):
            self.env[name] = (
                Pointer("parameter", (function.ea, n))
                if function.varinfo.get(name, {}).get("pointer")
                else Unknown("parameter " + str(n))
            )

    def tick(self):
        self.steps += 1
        if self.steps > self.max_steps:
            raise BudgetExceeded("partial evaluation budget reached")

    def state(self):
        return (copy.deepcopy(self.env), self.memory.clone(), self.contexts.clone())

    def restore(self, s):
        self.env, self.memory, self.contexts = s

    def address(self, e):
        if e is None:
            return UNKNOWN
        if e.op == "var":
            info = self.function.varinfo.get(e.value, {})
            return (
                Pointer("stack", self.frame, info["stkoff"])
                if info.get("stkoff") is not None
                else Pointer("local", (self.frame, e.value))
            )
        if e.op == "global":
            return Pointer("image", e.value)
        if e.op == "load":
            return self.eval(e.args[0])
        if e.op == "index":
            base = self.eval(e.args[0])
            off = self.eval(e.args[1])
            return (
                base.add(off * e.scale)
                if isinstance(base, Pointer) and isinstance(off, int)
                else UNKNOWN
            )
        if e.op == "member":
            base = (
                self.address(e.args[0]) if e.value.get("ref") else self.eval(e.args[0])
            )
            return base.add(e.value["offset"]) if isinstance(base, Pointer) else UNKNOWN
        return self.eval(e)

    def assign(self, target, value):
        value = self.trim(value, target.bits)
        if target.op == "var":
            self.env[target.value] = value
            self.memory.store(
                self.address(target),
                value,
                max(1, target.bits // 8 or self.pointer_size),
            )
        else:
            self.memory.store(
                self.address(target), value, max(1, target.bits // 8 or 1)
            )
        return value

    def value(self, e):
        v = self.eval(e)
        return v if isinstance(v, int) else None

    def eval_input(self, e):
        """A consumed return value may need a deeper getter chain than a void wrapper."""
        self.value_context += 1
        try:
            return self.eval(e)
        finally:
            self.value_context -= 1

    @staticmethod
    def trim(v, bits):
        if isinstance(v, Residue) and bits and bits <= v.bits:
            return v.value & ((1 << bits) - 1)
        if isinstance(v, Affine) and bits:
            return Affine(v.space, v.base, v.coefficient, v.offset, min(bits, v.bits))
        return v & ((1 << bits) - 1) if isinstance(v, int) and 0 < bits <= 128 else v

    def eval(self, e):
        if e is None:
            return UNKNOWN
        self.tick()
        op = e.op
        if op == "num":
            return self.trim(e.value, e.bits)
        if op == "literal_bytes":
            return Tagged("literal_bytes", bytes.fromhex(e.value))
        if op == "string":
            return Tagged("string", e.value)
        if op == "wide_string":
            return Tagged("wide_string", e.value)
        if op == "addr":
            return Pointer("image", e.value)
        if op == "var":
            if self.function.varinfo.get(e.value, {}).get("array"):
                return self.address(e)
            p = self.address(e)
            size = max(1, e.bits // 8 or self.pointer_size)
            memvalue = self.memory.load(p, size)
            if not isinstance(memvalue, Unknown):
                return memvalue
            if self.memory.key(p) in self.memory.cells:
                return memvalue
            v = self.env.get(e.value)
            return (
                v
                if v is not None
                else self.memory.load(
                    self.address(e), max(1, e.bits // 8 or self.pointer_size)
                )
            )
        if op == "global":
            if e.value is None:
                return UNKNOWN
            p = Pointer("image", e.value)
            if e.scale:
                return p
            v = self.memory.load(p, max(1, e.bits // 8 or self.pointer_size))
            return (
                Pointer("image", v)
                if e.text == "pointer_global" and isinstance(v, int) and v
                else v
            )
        if op == "ref":
            return self.address(e.args[0])
        if op in ("load", "index", "member"):
            return self.memory.load(self.address(e), max(1, e.bits // 8 or 1))
        if op == "assign":
            return self.assign(e.args[0], self.eval_input(e.args[1]))
        if op.startswith("assign_"):
            action = op[len("assign_") :]
            v = self.eval(type(e)(action, [e.args[0], e.args[1]], bits=e.args[0].bits))
            return self.assign(e.args[0], v)
        if op in ("preinc", "postinc", "predec", "postdec"):
            old = self.eval(e.args[0])
            inc = 1 if "inc" in op else -1
            if isinstance(old, int):
                new = self.trim(old + inc, e.args[0].bits)
            elif isinstance(old, Pointer):
                new = old.add(inc * e.scale)
            else:
                new = UNKNOWN
            self.assign(e.args[0], new)
            return old if op.startswith("post") else new
        if op == "cast":
            v = self.eval(e.args[0])
            if (
                e.value == "sint"
                and isinstance(v, int)
                and e.args[0].bits
                and e.bits > e.args[0].bits
            ):
                width = e.args[0].bits
                v = (
                    (v & ((1 << width) - 1)) - (1 << width)
                    if v & (1 << (width - 1))
                    else v
                )
            if e.value == "ptr" and isinstance(v, int) and v:
                return Pointer("image", v)
            if e.value == "int" and isinstance(v, Pointer):
                if v.address() is not None:
                    return self.trim(v.address(), e.bits)
                return Affine(
                    v.space, v.base, 1, v.offset, e.bits or self.pointer_size * 8
                )
            return self.trim(v, e.bits)
        if op == "call":
            return self.call(e)
        if op == "comma":
            self.eval(e.args[0])
            return self.eval(e.args[1])
        if op == "conditional":
            condition = self.eval(e.args[0])
            if isinstance(condition, int):
                return self.eval(e.args[1] if condition else e.args[2])
            start = self.state()
            self.conditional += 1
            try:
                a = self.eval(e.args[1])
                astate = self.state()
                self.restore(start)
                b = self.eval(e.args[2])
                bstate = self.state()
                self.restore(astate)
                self.env = {
                    k: v if bstate[0].get(k) == v else UNKNOWN
                    for k, v in astate[0].items()
                }
                self.memory.merge(bstate[1])
                self.contexts.merge(bstate[2])
            finally:
                self.conditional -= 1
            return a if a == b else UNKNOWN
        if op in ("logical_and", "logical_or"):
            a = self.eval(e.args[0])
            if isinstance(a, int):
                if op == "logical_and" and not a:
                    return 0
                if op == "logical_or" and a:
                    return 1
                b = self.eval(e.args[1])
                return int(bool(b)) if isinstance(b, int) else UNKNOWN
            start = self.state()
            self.conditional += 1
            try:
                b = self.eval(e.args[1])
                after = self.state()
                self.restore(start)
                self.env = {
                    k: v if after[0].get(k) == v else UNKNOWN
                    for k, v in start[0].items()
                }
                self.memory.merge(after[1])
                self.contexts.merge(after[2])
            finally:
                self.conditional -= 1
            if isinstance(b, int) and (
                (op == "logical_and" and not b) or (op == "logical_or" and b)
            ):
                return int(bool(b))
            return UNKNOWN
        if op in ("neg", "not", "logical_not"):
            a = self.eval(e.args[0])
            if not isinstance(a, int):
                return UNKNOWN
            return self.trim(
                -a if op == "neg" else ~a if op == "not" else int(not a), e.bits
            )
        if len(e.args) < 2:
            return UNKNOWN
        a = self.eval(e.args[0])
        b = self.eval(e.args[1])
        if op in ("ptradd", "ptrsub"):
            return (
                a.add(b * e.scale * (1 if op == "ptradd" else -1))
                if isinstance(a, Pointer) and isinstance(b, int)
                else UNKNOWN
            )
        if op == "add" and isinstance(a, Pointer) and isinstance(b, int):
            return a.add(b * e.scale)
        if op == "add" and isinstance(b, Pointer) and isinstance(a, int):
            return b.add(a * e.scale)
        if op == "sub" and isinstance(a, Pointer) and isinstance(b, int):
            return a.add(-b * e.scale)
        if (
            op in ("sub", "eq", "ne", "lt", "le", "gt", "ge")
            and isinstance(a, Pointer)
            and isinstance(b, Pointer)
            and a.space == b.space == "image"
        ):
            av, bv = a.address(), b.address()
            return {
                "sub": av - bv,
                "eq": int(av == bv),
                "ne": int(av != bv),
                "lt": int(av < bv),
                "le": int(av <= bv),
                "gt": int(av > bv),
                "ge": int(av >= bv),
            }[op]
        if (
            op in ("sub", "eq", "ne", "lt", "le", "gt", "ge")
            and isinstance(a, Pointer)
            and isinstance(b, Pointer)
            and (a.space, a.base) == (b.space, b.base)
        ):
            values = {
                "sub": a.offset - b.offset,
                "eq": int(a.offset == b.offset),
                "ne": int(a.offset != b.offset),
                "lt": int(a.offset < b.offset),
                "le": int(a.offset <= b.offset),
                "gt": int(a.offset > b.offset),
                "ge": int(a.offset >= b.offset),
            }
            return values[op]
        if (
            op in ("add", "sub")
            and isinstance(a, (int, Affine, Residue))
            and isinstance(b, (int, Affine, Residue))
            and not (isinstance(a, int) and isinstance(b, int))
        ):
            sign = 1 if op == "add" else -1
            if (
                isinstance(a, Affine)
                and isinstance(b, Affine)
                and (a.space, a.base) == (b.space, b.base)
            ):
                coef = a.coefficient + sign * b.coefficient
                off = a.offset + sign * b.offset
                known = min(a.bits, b.bits)
                result = (
                    Affine(a.space, a.base, coef, off, known)
                    if coef
                    else Residue(off & ((1 << known) - 1), known)
                )
                return self.trim(result, e.bits)
            if isinstance(a, int) and isinstance(b, Affine):
                return self.trim(
                    Affine(
                        b.space,
                        b.base,
                        sign * b.coefficient,
                        a + sign * b.offset,
                        b.bits,
                    ),
                    e.bits,
                )
            if isinstance(a, Affine) and isinstance(b, int):
                return self.trim(
                    Affine(a.space, a.base, a.coefficient, a.offset + sign * b, a.bits),
                    e.bits,
                )
            if isinstance(a, Residue) and isinstance(b, int):
                return self.trim(Residue(a.value + sign * b, a.bits), e.bits)
            if isinstance(a, int) and isinstance(b, Residue):
                return self.trim(Residue(a + sign * b.value, b.bits), e.bits)
        if not isinstance(a, int) or not isinstance(b, int):
            if (
                op in ("eq", "ne")
                and type(a) is type(b)
                and isinstance(a, (Pointer, Tagged))
            ):
                return int((a == b) if op == "eq" else (a != b))
            return UNKNOWN
        bits = e.bits or e.args[0].bits or 32
        if op in ("slt", "sle", "sgt", "sge", "sdiv", "smod"):

            def signed(v, width):
                v &= (1 << width) - 1
                return v - (1 << width) if v & (1 << (width - 1)) else v

            a = signed(a, e.args[0].bits or bits)
            b = signed(b, e.args[1].bits or bits)
            if op in ("sdiv", "smod"):
                if b == 0:
                    return UNKNOWN
                q = (abs(a) // abs(b)) * (-1 if (a < 0) != (b < 0) else 1)
                return self.trim(q if op == "sdiv" else a - q * b, bits)
            return {"slt": a < b, "sle": a <= b, "sgt": a > b, "sge": a >= b}[op] * 1
        if op in ("shl", "shr", "sar") and not 0 <= b < bits:
            return Unknown("undefined C shift count")
        try:
            operations = {
                "add": lambda: a + b,
                "sub": lambda: a - b,
                "mul": lambda: a * b,
                "xor": lambda: a ^ b,
                "and": lambda: a & b,
                "or": lambda: a | b,
                "shl": lambda: a << b,
                "shr": lambda: (a & ((1 << bits) - 1)) >> b,
                "sar": lambda: ((a - (1 << bits)) if a & (1 << (bits - 1)) else a) >> b,
                "div": lambda: a // b,
                "mod": lambda: a % b,
                "eq": lambda: int(a == b),
                "ne": lambda: int(a != b),
                "lt": lambda: int(a < b),
                "le": lambda: int(a <= b),
                "gt": lambda: int(a > b),
                "ge": lambda: int(a >= b),
                "logical_and": lambda: int(bool(a) and bool(b)),
                "logical_or": lambda: int(bool(a) or bool(b)),
                "rol": lambda: (
                    (a << (b % bits)) | ((a & ((1 << bits) - 1)) >> (bits - b % bits))
                ),
                "ror": lambda: (
                    ((a & ((1 << bits) - 1)) >> (b % bits)) | (a << (bits - b % bits))
                ),
            }
            return self.trim(operations[op](), bits) if op in operations else UNKNOWN
        except (ZeroDivisionError, OverflowError, ValueError):
            return UNKNOWN

    def call(self, e):
        target = dict(e.value) if isinstance(e.value, dict) else e.value or {}
        resolved_function = None
        if (
            isinstance(target, dict)
            and not target.get("target")
            and e.callee is not None
        ):
            pointer = self.eval_input(e.callee)
            address = (
                pointer.address()
                if isinstance(pointer, Pointer)
                else pointer if isinstance(pointer, int) else None
            )
            resolved_function = (
                self.lookup(address) if address and self.lookup else None
            )
            if resolved_function is not None and resolved_function.ea != address:
                resolved_function = None
            if resolved_function is not None:
                target.update(target=resolved_function.ea, name=resolved_function.name)
            else:
                self.diagnostics.append(
                    "Unresolved function-pointer call at %#x; no target guessed." % e.ea
                )
        name = normalize_name(
            target.get("name", "") if isinstance(target, dict) else target
        )
        values = []
        argument_providers = []
        for index, arg in enumerate(e.args):
            before = len(self.calls)
            values.append(self.eval_input(arg))
            providers = sorted(
                {c["target"] for c in self.calls[before:] if c.get("target")}
            )
            if providers:
                argument_providers.append(
                    dict(argument=index, function_addresses=providers[:64])
                )
        self.calls.append(
            dict(
                ea=e.ea,
                name=name,
                target=target.get("target") if isinstance(target, dict) else None,
                function=self.function.ea,
                args=e.args,
                values=values,
                memory=self.memory.clone(),
                resolved_indirect=resolved_function is not None,
                argument_providers=argument_providers,
            )
        )
        vector = evaluate_simd(name, values, self.memory)
        if vector is not None:
            return vector
        desc = cipher_descriptor(name)
        if desc:
            return Tagged("cipher", desc)
        if name.startswith("EVP_sha") or name == "EVP_md5":
            return Tagged("hash", name.removeprefix("EVP_"))
        if name in ("memcpy", "memmove", "qmemcpy") and len(values) >= 3:
            dest, src, n = values[:3]
            if (
                isinstance(dest, Pointer)
                and isinstance(src, (Pointer, Tagged))
                and isinstance(n, int)
                and 0 <= n <= 4096
            ):
                data = (
                    self.memory.bytes(src, n)
                    if isinstance(src, Pointer)
                    else read_bytes(self.memory, src, n)
                )
                self.memory.write(dest, data if data is not None else [None] * n)
                for key, v in list(self.env.items()):
                    if (
                        self.address(type(e)("var", value=key)) == dest
                        and n <= self.pointer_size
                    ):
                        self.env.pop(key, None)
            else:
                self.memory.invalidate(dest, n if isinstance(n, int) else None)
            return dest
        if name in ("memset", "bzero") and len(values) >= 2:
            dest = values[0]
            n = values[2] if name == "memset" and len(values) > 2 else values[1]
            byte = (
                values[1] & 255
                if name == "memset" and isinstance(values[1], int)
                else 0
            )
            if isinstance(dest, Pointer) and isinstance(n, int) and 0 <= n <= 4096:
                self.memory.write(dest, [byte] * n)
            else:
                self.memory.invalidate(dest, n if isinstance(n, int) else None)
            return dest
        if name in ("strcpy", "stpcpy") and len(values) >= 2:
            text = read_string(self.memory, values[1], limit=4096)
            if isinstance(values[0], Pointer) and text is not None:
                self.memory.write(values[0], list(text.encode() + b"\0"))
            else:
                self.memory.invalidate(values[0])
            return values[0]
        if name in ("printf", "mingw_printf", "puts", "putchar", "fputs", "fprintf"):
            # Avoid descending into CRT formatting engines. A possible %n stays conservative.
            format_index = 1 if name == "fprintf" else 0
            fmt = (
                read_string(self.memory, values[format_index])
                if len(values) > format_index
                else None
            )
            if name not in ("puts", "putchar", "fputs") and (
                fmt is None or "%n" in fmt
            ):
                for v in values[format_index + 1 :]:
                    if isinstance(v, Pointer):
                        self.memory.invalidate(v)
            return Unknown("formatting/IO return")
        if name in (
            "malloc",
            "calloc",
            "EVP_CIPHER_CTX_new",
            "RSA_new",
            "EVP_PKEY_CTX_new",
            "EVP_PKEY_CTX_new_id",
        ):
            return Pointer("heap", (self.frame, e.ea, self.steps))
        if name in ("read", "fread", "fgets", "recv"):
            pos = 1 if name in ("read", "recv") else 0
            self.memory.invalidate(values[pos] if len(values) > pos else None)
            return Unknown("file/network input")
        spec = self.catalog.lookup(name)
        if spec:
            decoder = ApiDecoder(self.contexts, self.pointer_size)
            if len(values) < spec["argc"]:
                values += [Unknown("argument missing")] * (spec["argc"] - len(values))
            finding, ctx = decoder.decode(
                name,
                spec,
                values,
                self.memory,
                e.ea,
                self.function.ea,
                "static",
                bool(self.conditional),
            )
            self.findings.append(finding)
            if argument_providers:
                finding.metadata["argument_providers"] = argument_providers
            event = spec["event"]
            if event == "cipher_fetch":
                ni = spec["fields"][0]["arg"]
                s = read_string(self.memory, values[ni])
                parsed = parse_cipher_string(s) if s else None
                return Tagged("cipher", parsed) if parsed else UNKNOWN
            if event in ("cng_open", "cng_key", "cng_import", "capi_import"):
                out = values[spec["output_arg"]]
                tag = Tagged("created_handle", (self.frame, e.ea))
                self.memory.store(out, tag, self.pointer_size)
                self.contexts.values[context_key(tag)] = ctx
            if event == "bignum_import":
                tag = Tagged("bignum", (self.frame, e.ea))
                self.contexts.values[context_key(tag)] = ctx
                return tag
            if event in ("random", "kdf"):
                oi = spec.get("random_output_arg", spec.get("derived_output_arg"))
                li = spec.get("random_length_arg", spec.get("derived_length_arg"))
                self.memory.invalidate(
                    values[oi], values[li] if isinstance(values[li], int) else None
                )
            for output in spec.get("writes", []):
                at = values[output["arg"]]
                n = (
                    values[output["length_arg"]]
                    if output.get("length_arg") is not None
                    else output.get("length")
                )
                if isinstance(at, Pointer) and n != 0:
                    self.memory.invalidate(
                        at, n if isinstance(n, int) and n >= 0 else None
                    )
            return Unknown("API result / success not evaluated")
        # Bounded wrapper traversal; do not emulate crypto internals or infinite recursion.
        depth_limit = 64 if self.value_context else 3
        fn = resolved_function or (
            self.lookup(target.get("target"))
            if self.lookup and isinstance(target, dict) and target.get("target")
            else None
        )
        if fn and self.depth >= depth_limit:
            self.diagnostics.append(
                "Return-value/call depth limit %d at %#x; result unresolved."
                % (depth_limit, e.ea)
            )
            fn = None
        call_key = (fn.ea, tuple(repr(v) for v in values)) if fn else None
        if fn and call_key in self.call_chain:
            self.diagnostics.append(
                "Recursive getter/call cycle at %#x; result unresolved." % e.ea
            )
            fn = None
        forwarded_key = getattr(fn, "forwarded_crypto_key_arg", None) if fn else None
        if fn and forwarded_key is not None:
            # A proven sole-call crypto forwarder has no raw output model.
            # Keep its call record/key snapshot, without repeatedly descending
            # through thunks (whose decompiled return value may be fictitious).
            for index, value in enumerate(values):
                if index != forwarded_key and isinstance(value, Pointer):
                    self.memory.invalidate(value)
            return Unknown("forwarded crypto output not statically emulated")
        if fn and getattr(fn, "crypto_primitive", False):
            modified = set()
            for node in fn.expressions():
                if node.op == "assign" or node.op.startswith("assign_"):
                    dest = node.args[0]
                    if dest.op in ("index", "load", "member"):
                        modified.update(
                            x.value
                            for x in dest.walk()
                            if x.op == "var" and x.value in fn.params
                        )
            for index, name in enumerate(fn.params):
                if name in modified and index < len(values):
                    writes = [
                        node.args[0]
                        for node in fn.expressions()
                        if (node.op == "assign" or node.op.startswith("assign_"))
                        and node.args
                        and any(
                            x.op == "var" and x.value == name
                            for x in node.args[0].walk()
                        )
                    ]
                    if writes and all(
                        d.op == "index"
                        and d.args[0].op == "var"
                        and d.args[0].value == name
                        and d.args[1].op == "num"
                        and d.args[1].value >= 0
                        for d in writes
                    ):
                        n = max(
                            d.args[1].value * d.scale + max(1, d.bits // 8)
                            for d in writes
                        )
                        self.memory.invalidate(values[index], n)
                    else:
                        self.memory.invalidate(values[index])
            return Unknown("crypto primitive output not statically emulated")
        if fn and len(fn.body) < 160:
            child = Interpreter(
                fn,
                self.catalog,
                self.memory.reader,
                self.memory.endian,
                self.pointer_size,
                self.lookup,
                self.depth + 1,
                max_steps=min(3000, self.max_steps - self.steps),
                frame=("call", fn.ea, next(self.frame_ids)),
                frame_ids=self.frame_ids,
                call_chain=self.call_chain + (call_key,),
            )
            child.memory = self.memory
            child.contexts = self.contexts
            child.conditional = self.conditional
            child.value_context = self.value_context
            for arg, value in zip(fn.params, values):
                child.assign(
                    type(e)(
                        "var",
                        value=arg,
                        bits=fn.varinfo.get(arg, {}).get("bits", self.pointer_size * 8),
                    ),
                    value,
                )
            child.run()
            child.memory.release_frame(child.frame)
            self.memory = child.memory
            self.contexts = child.contexts
            self.findings += child.findings
            self.calls += child.calls
            self.diagnostics += child.diagnostics
            self.steps += child.steps
            return child.return_value
        for value in values:
            if isinstance(value, Pointer):
                self.memory.invalidate(value)
        return Unknown("unknown call " + name)

    def invalidate_writes(self, body):
        for s in body:
            for e in s.walk():
                if (
                    e.op == "assign"
                    or e.op.startswith("assign_")
                    or e.op in ("preinc", "postinc", "predec", "postdec")
                ):
                    target = e.args[0]
                    if target.op == "var":
                        self.env[target.value] = UNKNOWN
                        self.memory.invalidate(
                            self.address(target),
                            max(1, target.bits // 8 or self.pointer_size),
                        )
                    else:
                        self.memory.invalidate(self.address(target))

    def branch(self, yes, no):
        start = self.state()
        self.conditional += 1
        a_stops = False
        b_stops = False
        try:
            self.execute(yes)
        except StopPath:
            a_stops = True
        a = self.state()
        self.restore(start)
        try:
            self.execute(no)
        except StopPath:
            b_stops = True
        b = self.state()
        self.conditional -= 1
        if a_stops and not b_stops:
            self.restore(b)
            return
        if b_stops and not a_stops:
            self.restore(a)
            return
        self.restore(a)
        self.env = {
            key: value if b[0].get(key) == value else UNKNOWN
            for key, value in a[0].items()
        }
        self.memory.merge(b[1])
        self.contexts.merge(b[2])
        if a_stops and b_stops:
            raise StopPath()

    def record_return(self, value):
        """Keep every feasible return, including the memory at that exit."""
        if isinstance(value, Pointer) and (
            value.space == "stack"
            and value.base == self.frame
            or value.space == "local"
            and isinstance(value.base, tuple)
            and value.base[0] == self.frame
        ):
            value = Unknown("returned address of callee stack/local")
        self.return_paths.append((value, self.state()))
        if len(self.return_paths) > 32:
            self.merge_return_paths()
            self.return_paths = [(self.return_value, self.state())]

    def merge_return_paths(self):
        value, state = self.return_paths[0]
        self.restore(state)
        for other_value, other in self.return_paths[1:]:
            if value != other_value:
                value = Unknown("conflicting/unknown function return paths")
            self.env = {
                k: v if other[0].get(k) == v else UNKNOWN for k, v in self.env.items()
            }
            self.memory.merge(other[1])
            self.contexts.merge(other[2])
        self.return_value = value

    def execute(self, body):
        for s in body:
            self.tick()
            if s.op == "block":
                self.execute(s.body)
            elif s.op == "expr":
                self.eval(s.expr)
            elif s.op == "return":
                # Inherit whether the caller actually consumes this result.
                # Hex-Rays may render a void/tail wrapper as `return f()`;
                # that alone must not turn every wrapper into a deep getter.
                self.record_return(self.eval(s.expr))
                raise StopPath()
            elif s.op == "break":
                raise BreakLoop()
            elif s.op == "if":
                c = self.eval(s.expr)
                if isinstance(c, int):
                    self.execute(s.body if c else s.other)
                else:
                    self.branch(s.body, s.other)
            elif s.op in ("for", "while", "do"):
                if s.init:
                    self.eval(s.init)
                for iteration in range(1024):
                    c = 1 if s.op == "do" and iteration == 0 else self.eval(s.expr)
                    if isinstance(c, int) and not c:
                        break
                    if not isinstance(c, int):
                        start = self.state()
                        self.conditional += 1
                        try:
                            self.execute(s.body)
                        except BreakLoop:
                            pass
                        except StopPath:
                            # A possible loop iteration returned; zero iterations
                            # still reach the code after the loop.
                            pass
                        self.conditional -= 1
                        possible = self.state()
                        self.restore(start)
                        self.memory.merge(possible[1])
                        self.contexts.merge(possible[2])
                        self.invalidate_writes(s.body)
                        break
                    try:
                        self.execute(s.body)
                    except BreakLoop:
                        break
                    if s.step:
                        self.eval(s.step)
                else:
                    self.invalidate_writes(s.body)
                    self.diagnostics.append("loop iteration limit at %#x" % s.ea)
            elif s.op in ("goto", "unknown", "switch"):
                self.invalidate_writes(s.body + s.other)
                self.diagnostics.append(
                    "unsupported control flow at %#x; downstream values may be unresolved"
                    % s.ea
                )
                # Never linearly trust assignments past arbitrary jumps/switches.
                for name in list(self.env):
                    self.env[name] = UNKNOWN
                self.record_return(Unknown("unsupported control flow"))
                raise StopPath()

    def run(self):
        falls_through = False
        try:
            self.execute(self.function.body)
            falls_through = True
        except StopPath:
            pass
        except BreakLoop:
            self.record_return(Unknown("unresolved break/control path"))
        except BudgetExceeded as e:
            self.diagnostics.append(str(e) + " at " + hex(self.function.ea))
            # The budget is already exhausted: do not evaluate addresses or
            # helper calls while invalidating state, which would throw again.
            self.memory.tainted.add(("image", 0))
            self.memory.tainted.update(k[:2] for k in self.memory.cells)
            for key in self.memory.cells:
                self.memory.cells[key] = None
            self.memory.objects.clear()
            self.env = {name: UNKNOWN for name in self.env}
            self.contexts = Contexts()
            self.record_return(Unknown("partial evaluation budget reached"))
        if falls_through or not self.return_paths:
            self.record_return(Unknown("function ended without a proven return value"))
        self.merge_return_paths()
        return self
