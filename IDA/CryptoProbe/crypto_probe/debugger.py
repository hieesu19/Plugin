"""IDA debugger integration: observed runtime buffers, owned breakpoints, no auto-resume."""

import traceback
import ida_dbg, ida_idd, ida_idaapi, ida_nalt, ida_ua, ida_idp, ida_kernwin, idc
from .runtime import RuntimeEngine
from .ida_adapter import architecture

GROUP = "Crypto Probe (owned)"


def live_read(ea, size):
    if size < 0 or size > 65536:
        return None
    if size == 0:
        return b""
    try:
        return ida_idd.dbg_read_memory(ea, size)
    except Exception:
        return None


class Debugger(ida_dbg.DBG_Hooks):
    def __init__(self, bindings=None, notify=None, abi=None):
        super().__init__()
        self.bindings = dict(bindings or {})
        self.notify = notify
        self.arch = architecture()
        self.abi = abi or self.arch["abi"]
        self.engine = RuntimeEngine(
            self.abi, ida_dbg.get_reg_val, live_read, self.arch["endian"]
        )
        self.owned = {}
        self.shared = set()
        self.returns = set()
        self.enabled = False
        self.delta = 0
        self.imagebase = ida_nalt.get_imagebase()
        self.errors = []

    def mark(self, ea):
        existing = ida_dbg.bpt_t()
        if ida_dbg.get_bpt(ea, existing):
            self.shared.add(ea)
            return True
        if not ida_dbg.add_bpt(ea, 0, ida_idd.BPT_SOFT):
            return False
        bp = ida_dbg.bpt_t()
        if ida_dbg.get_bpt(ea, bp):
            ida_dbg.set_bpt_group(bp, GROUP)
            self.owned[ea] = dict(
                type=bp.type, condition=bp.condition, logical_ea=ea - self.delta
            )
        return True

    def arm(self, addresses=None):
        addresses = list(addresses) if addresses is not None else list(self.bindings)
        if len(addresses) > 512:
            raise ValueError(
                "Select a smaller scope; automatic capture is limited to 512 callsites per session."
            )
        if not self.enabled:
            self.hook()
            self.enabled = True
        ok = []
        failed = []
        for ea in addresses:
            ins = ida_ua.insn_t()
            if not ida_ua.decode_insn(ins, ea) or not ida_idp.is_call_insn(ins):
                failed.append(ea)
                continue
            if ea not in self.bindings:
                failed.append(ea)
                continue
            if self.bindings[ea].get("candidate"):
                failed.append(ea)
                continue
            if self.mark(ea):
                ok.append(ea)
            else:
                failed.append(ea)
        return dict(armed=ok, skipped=failed, shared=list(self.shared))

    def disarm(self):
        for old, snapshot in list(self.owned.items()):
            logical = snapshot["logical_ea"]
            candidates = {old, logical, logical + self.delta}
            for ea in candidates:
                bp = ida_dbg.bpt_t()
                if not ida_dbg.get_bpt(ea, bp):
                    continue
                # Preserve a breakpoint if the user changed its type/condition/group.
                if (
                    bp.type == snapshot["type"]
                    and bp.condition == snapshot["condition"]
                    and ida_dbg.get_bpt_group(bp.loc) == GROUP
                ):
                    ida_dbg.del_bpt(ea)
        self.owned.clear()
        self.returns.clear()
        self.shared.clear()
        if self.enabled:
            self.unhook()
            self.enabled = False

    def select(self, tid):
        old = ida_dbg.get_current_thread()
        if tid != old and not ida_dbg.select_thread(tid):
            raise ValueError("Cannot select breakpoint thread")
        return old

    def binding_at(self, ea):
        return self.bindings.get(ea) or self.bindings.get(ea - self.delta)

    def capture_at(self, ea, tid=None, entry_binding=None):
        if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
            raise ValueError(
                "Debugger must be suspended before reading live arguments."
            )
        tid = tid if tid is not None else ida_dbg.get_current_thread()
        old = self.select(tid)
        try:
            ida_dbg.refresh_debugger_memory()
            binding = entry_binding or self.binding_at(ea)
            if not binding:
                raise ValueError(
                    "No API/manual binding at current instruction. Scan or bind the function first."
                )
            ins = ida_ua.insn_t()
            is_call = ida_ua.decode_insn(ins, ea) and ida_idp.is_call_insn(ins)
            if not is_call and not entry_binding:
                raise ValueError(
                    "Current address is not a call instruction; choose a function-entry binding explicitly."
                )
            if entry_binding:
                sp = self.engine.abi.reg(self.engine.abi.sp)
                if self.abi in (
                    "win64",
                    "sysv64",
                    "cdecl32",
                    "stdcall32",
                    "fastcall32",
                ):
                    raw = (
                        live_read(sp, self.engine.abi.word)
                        if isinstance(sp, int)
                        else None
                    )
                    ret = int.from_bytes(raw, self.arch["endian"]) if raw else None
                else:
                    lr = self.engine.abi.reg("X30" if self.abi == "aarch64" else "LR")
                    ret = lr if isinstance(lr, int) else None
                site = "entry"
            else:
                ret = ea + ins.size
                site = "call"
            f = self.engine.capture(binding, ea, tid, ret, site)
            if ret is not None:
                if self.mark(ret):
                    self.returns.add((tid, ret))
                else:
                    self.engine.pending.pop((tid, ret), None)
                    f.notes.append(
                        "Could not place return breakpoint; input observed, output/handle effect unavailable."
                    )
            if not self.enabled:
                self.hook()
                self.enabled = True
            if self.notify:
                self.notify(f)
            return f
        finally:
            if old != tid:
                ida_dbg.select_thread(old)

    def dbg_bpt(self, tid, ea):
        try:
            # The event happens while suspended; never request continue/step from this hook.
            if (tid, ea) in self.engine.pending:
                old = self.select(tid)
                try:
                    ida_dbg.refresh_debugger_memory()
                    f = self.engine.finish(ea, tid)
                    if f and self.notify:
                        self.notify(f)
                finally:
                    if old != tid:
                        ida_dbg.select_thread(old)
            if self.binding_at(ea):
                if ida_dbg.get_ip_val() == ea:
                    self.capture_at(ea, tid)
        except Exception as exc:
            self.errors.append("Capture at %#x: %s" % (ea, exc))
            ida_kernwin.msg("[Crypto Probe] %s\n" % self.errors[-1])
        return 0

    def dbg_process_start(self, pid, tid, ea, name, base, size):
        self.engine.reset()
        self.delta = base - self.imagebase

    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        self.engine.reset()
        self.delta = base - self.imagebase

    def dbg_process_exit(self, pid, tid, ea, code):
        self.engine.pending.clear()
        self.returns.clear()
        self.engine.contexts.values.clear()

    def dbg_process_detach(self, pid, tid, ea):
        self.engine.pending.clear()
        self.returns.clear()
        self.engine.contexts.values.clear()
