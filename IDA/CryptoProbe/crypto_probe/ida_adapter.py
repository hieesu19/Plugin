"""IDA-specific lifting/reading. Imported lazily so core tests require no IDA."""

import re
import idaapi, ida_ida, ida_idaapi, ida_bytes, ida_funcs, ida_idp, ida_lines, ida_nalt, ida_segment, ida_ua, ida_kernwin
import idautils, idc
from .ir import Expr, Stmt, FunctionIR

BADADDR = ida_idaapi.BADADDR


def architecture():
    bits = (
        64 if ida_ida.inf_is_64bit() else 32 if ida_ida.inf_is_32bit_exactly() else 16
    )
    proc = ida_ida.inf_get_procname()
    ft = ida_ida.inf_get_filetype()
    pe = ft == ida_ida.f_PE
    return dict(
        bits=bits,
        processor=proc,
        endian="big" if ida_ida.inf_is_be() else "little",
        format="PE" if pe else "ELF" if ft == ida_ida.f_ELF else "other",
        abi=(
            "win64"
            if bits == 64 and proc == "metapc" and pe
            else (
                "sysv64"
                if bits == 64 and proc == "metapc"
                else (
                    "cdecl32"
                    if proc == "metapc"
                    else (
                        "aarch64"
                        if bits == 64 and proc == "ARM"
                        else "arm32" if proc == "ARM" else "unsupported"
                    )
                )
            )
        ),
    )


def read_image(ea, size):
    if size < 0 or size > 1048576 or ea == BADADDR:
        return None
    if size == 0:
        return b""
    # get_bytes may include undefined bytes; check initialized flags before trusting a key.
    if not ida_bytes.is_loaded(ea) or not ida_bytes.is_loaded(ea + size - 1):
        return None
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None or len(raw) != size:
        return None
    if not all(ida_bytes.is_loaded(ea + i) for i in range(size)):
        return None
    return raw


def plain_name(ea):
    return ida_name_at(ea)


def ida_name_at(ea):
    return idc.get_name(ea) or ida_funcs.get_func_name(ea) or ""


def target_name(ea):
    name = ida_name_at(ea)
    fn = ida_funcs.get_func(ea)
    if fn and fn.flags & ida_funcs.FUNC_THUNK:
        try:
            target = ida_funcs.calc_thunk_func_target(fn)
            if isinstance(target, tuple):
                target = target[0]
            if target is not None and target != BADADDR:
                name = ida_name_at(target) or name
        except Exception:
            pass
    return name


def lift_instructions(ea):
    fn = ida_funcs.get_func(ea)
    if not fn:
        return []
    out = []
    for address in idautils.FuncItems(fn.start_ea):
        if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
            continue
        ins = ida_ua.insn_t()
        if not ida_ua.decode_insn(ins, address):
            continue
        mnemonic = idc.print_insn_mnem(address).lower()
        immediates = []
        call = None
        for op in ins.ops:
            if op.type == ida_ua.o_void:
                break
            if op.type == ida_ua.o_imm:
                immediates.append(op.value)
        if ida_idp.is_call_insn(ins):
            candidates = [
                x.to
                for x in idautils.XrefsFrom(address, 0)
                if x.type in (idc.fl_CN, idc.fl_CF, idc.dr_R, idc.dr_O)
            ]
            for target in candidates:
                if target_name(target):
                    call = dict(target=target, name=target_name(target))
                    break
            if call is None and ins.ops[0].type in (ida_ua.o_near, ida_ua.o_mem):
                target = ins.ops[0].addr
                call = dict(target=target, name=target_name(target))
        out.append(
            dict(
                ea=address,
                size=ins.size,
                mnemonic=mnemonic,
                immediates=immediates,
                call=call,
            )
        )
    return out


def decompiler_available():
    try:
        import ida_hexrays as h

        return bool(h.init_hexrays_plugin())
    except ImportError:
        return False


def typename_bits(t):
    try:
        n = t.get_size()
        return n * 8 if 0 < n <= 256 else 0
    except Exception:
        return 0


class CtreeLifter:
    def __init__(self, cfunc):
        import ida_hexrays as h

        self.h = h
        self.cfunc = cfunc
        self.vars = {}
        self.names = {}
        self.params = []
        for i, v in enumerate(cfunc.get_lvars()):
            key = "v%d" % i
            self.names[i] = key
            info = dict(
                name=v.name,
                bits=typename_bits(v.type()),
                pointer=v.type().is_ptr(),
                array=v.type().is_array(),
            )
            try:
                if v.is_stk_var():
                    info["stkoff"] = v.get_stkoff()
                    info["stkoff_delta"] = cfunc.get_stkoff_delta()
                if v.is_arg_var():
                    self.params.append(key)
            except Exception:
                pass
            self.vars[key] = info
        try:
            self.params = [self.names[i] for i in cfunc.argidx]
        except Exception:
            pass
        self.operations = {}
        mapping = {
            "cot_add": "add",
            "cot_sub": "sub",
            "cot_mul": "mul",
            "cot_band": "and",
            "cot_bor": "or",
            "cot_xor": "xor",
            "cot_shl": "shl",
            "cot_ushr": "shr",
            "cot_sshr": "sar",
            "cot_udiv": "div",
            "cot_sdiv": "sdiv",
            "cot_umod": "mod",
            "cot_smod": "smod",
            "cot_eq": "eq",
            "cot_ne": "ne",
            "cot_slt": "slt",
            "cot_ult": "lt",
            "cot_sle": "sle",
            "cot_ule": "le",
            "cot_sgt": "sgt",
            "cot_ugt": "gt",
            "cot_sge": "sge",
            "cot_uge": "ge",
            "cot_land": "logical_and",
            "cot_lor": "logical_or",
            "cot_comma": "comma",
            "cot_asg": "assign",
            "cot_asgadd": "assign_add",
            "cot_asgsub": "assign_sub",
            "cot_asgxor": "assign_xor",
            "cot_asgband": "assign_and",
            "cot_asgbor": "assign_or",
            "cot_preinc": "preinc",
            "cot_postinc": "postinc",
            "cot_predec": "predec",
            "cot_postdec": "postdec",
            "cot_neg": "neg",
            "cot_bnot": "not",
            "cot_lnot": "logical_not",
        }
        for key, name in mapping.items():
            if hasattr(h, key):
                self.operations[getattr(h, key)] = name

    def element_size(self, t):
        try:
            return (
                max(1, min(t.get_ptrarr_objsize(), 256)) if t.is_ptr_or_array() else 1
            )
        except Exception:
            return 1

    def expr(self, e, depth=0):
        h = self.h
        if e is None or depth > 100:
            return Expr("unknown")
        op = e.op
        ea = e.ea if e.ea != BADADDR else self.cfunc.entry_ea
        bits = typename_bits(e.type)
        scale = 1
        if op == h.cot_num:
            try:
                value = e.numval()
            except Exception:
                value = e.n._value
            return Expr("num", value=value, bits=bits, ea=ea)
        if op == h.cot_var:
            return Expr(
                "var", value=self.names.get(e.v.idx, "unknown_var"), bits=bits, ea=ea
            )
        if op == h.cot_obj:
            import ida_typeinf

            original = ida_typeinf.tinfo_t()
            if ida_nalt.get_tinfo(original, e.obj_ea):
                is_array = original.is_array()
                is_func = original.is_func()
            else:
                is_array = e.type.is_array()
                is_func = e.type.is_func()
            if ida_bytes.is_strlit(ida_bytes.get_full_flags(e.obj_ea)):
                is_array = True
            return Expr(
                "global",
                value=e.obj_ea,
                bits=bits,
                ea=ea,
                text=(
                    "pointer_global"
                    if e.type.is_ptr() and not is_array and not is_func
                    else ""
                ),
                scale=1 if is_array or is_func else 0,
            )
        if op == h.cot_str:
            from .literals import c_literal_bytes

            if self.element_size(e.type) == 1:
                raw = c_literal_bytes(e.string)
                return Expr(
                    "literal_bytes" if raw is not None else "unknown",
                    value=raw.hex() if raw is not None else None,
                    bits=bits,
                    ea=ea,
                )
            return Expr("wide_string", value=e.string, bits=bits, ea=ea)
        if op == h.cot_ref:
            return Expr("ref", [self.expr(e.x, depth + 1)], bits=bits, ea=ea)
        if op == h.cot_ptr:
            return Expr("load", [self.expr(e.x, depth + 1)], bits=bits, ea=ea)
        if op == h.cot_idx:
            return Expr(
                "index",
                [self.expr(e.x, depth + 1), self.expr(e.y, depth + 1)],
                bits=bits,
                ea=ea,
                scale=self.element_size(e.x.type),
            )
        if op == h.cot_sizeof:
            size = e.x.type.get_size()
            if size != BADADDR and size >= 0:
                return Expr("num", value=size, bits=bits, ea=ea)
        if op in (h.cot_memref, h.cot_memptr):
            return Expr(
                "member",
                [self.expr(e.x, depth + 1)],
                value={"ref": op == h.cot_memref, "offset": e.m},
                bits=bits,
                ea=ea,
            )
        if op == h.cot_cast:
            return Expr(
                "cast",
                [self.expr(e.x, depth + 1)],
                value=(
                    "ptr"
                    if e.type.is_ptr()
                    else "sint" if e.x.type.is_signed() else "int"
                ),
                bits=bits,
                ea=ea,
            )
        if op == h.cot_tern:
            return Expr(
                "conditional",
                [
                    self.expr(e.x, depth + 1),
                    self.expr(e.y, depth + 1),
                    self.expr(e.z, depth + 1),
                ],
                bits=bits,
                ea=ea,
            )
        if op == h.cot_call:
            target_expr = e.x
            while target_expr.op in (h.cot_cast, h.cot_ref):
                target_expr = target_expr.x
            target = target_expr.obj_ea if target_expr.op == h.cot_obj else None
            name = (
                target_name(target)
                if target is not None
                else target_expr.helper if target_expr.op == h.cot_helper else ""
            )
            args = [self.expr(a, depth + 1) for a in e.a]
            if (
                name
                in (
                    "__ROL1__",
                    "__ROL2__",
                    "__ROL4__",
                    "__ROL8__",
                    "__ROR1__",
                    "__ROR2__",
                    "__ROR4__",
                    "__ROR8__",
                )
                and len(args) == 2
            ):
                return Expr(
                    "rol" if "__ROL" in name else "ror",
                    args,
                    bits=bits or int(name[-3]) * 8,
                    ea=ea,
                )
            return Expr(
                "call",
                args,
                value={
                    "name": name,
                    "target": target,
                    "callee_expr": self.expr(target_expr, depth + 1).display(),
                },
                bits=bits,
                ea=ea,
                callee=(
                    self.expr(target_expr, depth + 1)
                    if target is None and target_expr.op != h.cot_helper
                    else None
                ),
            )
        if op in self.operations:
            name = self.operations[op]
            unary = name in (
                "preinc",
                "postinc",
                "predec",
                "postdec",
                "neg",
                "not",
                "logical_not",
            )
            args = [self.expr(e.x, depth + 1)]
            if not unary:
                args.append(self.expr(e.y, depth + 1))
            if name in ("add", "sub") and e.x.type.is_ptr():
                name = "ptradd" if name == "add" else "ptrsub"
                scale = self.element_size(e.x.type)
            return Expr(name, args, bits=bits, ea=ea, scale=scale)
        return Expr("unknown", bits=bits, ea=ea)

    def statement(self, s, depth=0):
        h = self.h
        if depth > 100:
            return Stmt("unknown")
        ea = s.ea if s.ea != BADADDR else self.cfunc.entry_ea
        if s.op == h.cit_block:
            return Stmt(
                "block", body=[self.statement(x, depth + 1) for x in s.cblock], ea=ea
            )
        if s.op == h.cit_expr:
            return Stmt("expr", self.expr(s.cexpr), ea=ea)
        if s.op == h.cit_if:
            return Stmt(
                "if",
                self.expr(s.cif.expr),
                body=[self.statement(s.cif.ithen, depth + 1)],
                other=[self.statement(s.cif.ielse, depth + 1)] if s.cif.ielse else [],
                ea=ea,
            )
        if s.op == h.cit_for:
            return Stmt(
                "for",
                self.expr(s.cfor.expr),
                body=[self.statement(s.cfor.body, depth + 1)],
                init=self.expr(s.cfor.init),
                step=self.expr(s.cfor.step),
                ea=ea,
            )
        if s.op == h.cit_while:
            return Stmt(
                "while",
                self.expr(s.cwhile.expr),
                body=[self.statement(s.cwhile.body, depth + 1)],
                ea=ea,
            )
        if s.op == h.cit_do:
            return Stmt(
                "do",
                self.expr(s.cdo.expr),
                body=[self.statement(s.cdo.body, depth + 1)],
                ea=ea,
            )
        if s.op == h.cit_return:
            return Stmt("return", self.expr(s.creturn.expr), ea=ea)
        if s.op == h.cit_break:
            return Stmt("break", ea=ea)
        if s.op == h.cit_goto:
            return Stmt("goto", ea=ea)
        if s.op == h.cit_empty:
            return Stmt("block", ea=ea)
        if s.op == h.cit_switch:
            return Stmt(
                "switch",
                self.expr(s.cswitch.expr),
                body=[self.statement(case, depth + 1) for case in s.cswitch.cases],
                ea=ea,
            )
        return Stmt("unknown", ea=ea)

    def lift(self):
        return FunctionIR(
            self.cfunc.entry_ea,
            ida_funcs.get_func_name(self.cfunc.entry_ea),
            [self.statement(self.cfunc.body)],
            self.params,
            self.vars,
            lift_instructions(self.cfunc.entry_ea),
        )


class IdaSource:
    def __init__(self):
        self.cache = {}
        self.errors = {}
        self.graph_cache = {}
        self.import_addresses = set()
        for index in range(ida_nalt.get_import_module_qty()):
            ida_nalt.enum_import_names(index, self._remember_import)
        self.hexrays = decompiler_available()
        self.arch = architecture()

    def _remember_import(self, ea, name, ordinal):
        self.import_addresses.add(ea)
        return True

    def function_start(self, ea):
        if ea is None or ea == BADADDR:
            return None
        fn = ida_funcs.get_func(ea)
        seg = ida_segment.getseg(ea)
        if (
            not fn
            or not seg
            or seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_NULL)
        ):
            return None
        return fn.start_ea

    def callees(self, ea):
        """Use code xrefs, including tail jumps; don't invoke Hex-Rays for discovery."""
        ea = self.function_start(ea)
        if ea is None:
            return [], 0
        if ea in self.graph_cache:
            return self.graph_cache[ea]
        caller = ida_funcs.get_func(ea)
        targets, unresolved = set(), 0
        for index, address in enumerate(idautils.FuncItems(ea)):
            if index % 256 == 0 and self.canceled():
                break
            if not ida_bytes.is_code(ida_bytes.get_full_flags(address)):
                continue
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, address):
                continue
            is_call = ida_idp.is_call_insn(ins)
            refs = list(idautils.XrefsFrom(address, 0))
            resolved_call = False
            for ref in refs:
                # Address-taken functions can be callback/provider arguments.
                # Discover possible code targets without decompiling or guessing
                # a particular target for an unresolved indirect call.
                if ref.type in (idc.dr_O, idc.dr_R):
                    pointed = self.function_start(ref.to)
                    if pointed is not None and pointed != ea:
                        targets.add(pointed)
                if ref.type not in (idc.fl_CN, idc.fl_CF, idc.fl_JN, idc.fl_JF):
                    continue
                if not is_call and ida_funcs.func_contains(caller, ref.to):
                    continue
                target = self.function_start(ref.to)
                if target is not None:
                    resolved_call = True
                    if target != ea:
                        targets.add(target)
                else:
                    seg = ida_segment.getseg(ref.to)
                    if seg and seg.type == ida_segment.SEG_XTRN:
                        resolved_call = True
            if is_call and not resolved_call:
                # A documented import slot is an external leaf, not an unknown dispatch.
                imported = any(ref.to in self.import_addresses for ref in refs)
                if not imported and ins.ops[0].type not in (
                    ida_ua.o_near,
                    ida_ua.o_far,
                ):
                    unresolved += 1
        value = sorted(targets), unresolved
        self.graph_cache[ea] = value
        return value

    def functions(self):
        return list(idautils.Functions())

    def function(self, ea):
        if ea is None:
            return None
        fn = ida_funcs.get_func(ea)
        if not fn:
            return None
        ea = fn.start_ea
        if ea in self.cache:
            return self.cache[ea]
        result = None
        if self.hexrays and fn.end_ea - fn.start_ea <= 262144:
            try:
                import ida_hexrays

                result = CtreeLifter(ida_hexrays.decompile(ea)).lift()
            except Exception as exc:
                self.errors[ea] = str(exc)
        if result is None:
            result = FunctionIR(
                ea, ida_funcs.get_func_name(ea), [], instructions=lift_instructions(ea)
            )
        self.cache[ea] = result
        return result

    def segments(self, max_bytes=134217728):
        total = 0
        for start in idautils.Segments():
            seg = ida_segment.getseg(start)
            if not seg or seg.type in (ida_segment.SEG_XTRN, ida_segment.SEG_NULL):
                continue
            end = seg.end_ea
            for address in range(start, end, 1048576):
                size = min(1048576, end - address)
                if total + size > max_bytes:
                    return
                data = ida_bytes.get_bytes(address, size)
                if data:
                    yield address, data
                total += size

    def canceled(self):
        return ida_kernwin.user_cancelled()
