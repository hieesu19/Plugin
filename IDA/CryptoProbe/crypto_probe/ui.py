"""Native IDA UI: no Qt/package installation or network dependencies."""

import json, traceback
from pathlib import Path
import idaapi, ida_auto, ida_kernwin, ida_funcs, ida_bytes, ida_nalt, ida_idaapi, ida_dbg, idc
from .model import ScanResult, merge_findings
from .apis import ApiCatalog, normalize_name
from .ida_adapter import IdaSource, read_image, target_name
from .scanner import Scanner
from .callgraph import collect_reachable
from .debugger import Debugger
from .exporter import crypto_draft, markdown_report

TITLE = "Crypto Probe — offline"


class DetailViewer(ida_kernwin.simplecustviewer_t):
    sequence = 0

    def show(self, f):
        DetailViewer.sequence += 1
        title = "Crypto Probe detail %#x #%d" % (f.address, DetailViewer.sequence)
        if not self.Create(title):
            return False
        for line in json.dumps(f.to_dict(hex_addresses=True), ensure_ascii=False, indent=2).splitlines():
            self.AddLine(line)
        self.Show()
        return True


class FindingsChooser(ida_kernwin.Choose):
    def __init__(self, controller):
        super().__init__(
            TITLE,
            [
                ["Address", 18],
                ["Function / API", 32],
                ["Algorithm", 20],
                ["Mode", 10],
                ["Confidence", 20],
                ["Source", 9],
                ["Materials", 70],
            ],
            flags=ida_kernwin.Choose.CH_CAN_REFRESH | ida_kernwin.Choose.CH_RESTORE,
        )
        self.controller = controller
        self.rows = []
        self.selected = 0
        self.filter = ""

    def rebuild(self):
        terms = self.filter.lower().split()
        self.rows = [
            f
            for f in self.controller.result.findings
            if all(
                t
                in (
                    f.algorithm
                    + " "
                    + f.mode
                    + " "
                    + f.api
                    + " "
                    + f.summary()
                    + " "
                    + f.source
                    + " "
                    + f.confidence
                ).lower()
                for t in terms
            )
        ]

    def OnGetSize(self):
        self.rebuild()
        return len(self.rows)

    def OnGetLine(self, n):
        f = self.rows[n]
        return [
            "%#x" % f.address,
            f.api or ida_funcs.get_func_name(f.function) or "%#x" % f.function,
            f.algorithm,
            f.mode,
            f.confidence,
            f.source,
            f.summary(),
        ]

    def OnSelectLine(self, n):
        self.selected = n
        if 0 <= n < len(self.rows):
            ida_kernwin.jumpto(self.rows[n].address)
            self.controller.detail(self.rows[n])
        return (self.NOTHING_CHANGED,)

    def OnSelectionChange(self, selection):
        if selection:
            self.selected = selection[0]

    def OnRefresh(self, n):
        self.rebuild()
        return (self.ALL_CHANGED, min(n, max(0, len(self.rows) - 1)))

    def chosen(self):
        return self.rows[self.selected] if 0 <= self.selected < len(self.rows) else None

    def show(self):
        self.rebuild()
        self.Show(False)
        widget = self.GetWidget()
        if widget:
            for name in (
                "detail",
                "jump",
                "copy_key",
                "copy_iv",
                "draft",
                "arm_selected",
                "annotate",
                "filter",
            ):
                ida_kernwin.attach_action_to_popup(widget, None, "crypto_probe:" + name)


class Handler(ida_kernwin.action_handler_t):
    def __init__(self, controller, name):
        super().__init__()
        self.controller = controller
        self.name = name

    def activate(self, ctx):
        try:
            self.controller.action(self.name, ctx)
        except Exception as e:
            ida_kernwin.warning("Crypto Probe: %s" % e)
            ida_kernwin.msg("[Crypto Probe] " + traceback.format_exc() + "\n")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("scan_all", "Scan database", "Ctrl-Alt-K"),
    ("scan_function", "Scan current function", "Ctrl-Alt-J"),
    ("scan_recursive", "Scan current function recursively", "Ctrl-Alt-R"),
    ("show", "Show results", ""),
    ("capture", "Capture current call / API entry", "Ctrl-Alt-L"),
    ("arm", "Arm known API callsites", ""),
    ("disarm", "Disarm capture / owned breakpoints", ""),
    ("abi", "Choose debugger ABI", ""),
    ("bind", "Bind current function arguments", ""),
    ("export", "Export full report", ""),
    ("draft", "Export selected Crypto draft", ""),
    ("detail", "Show selected evidence", ""),
    ("jump", "Jump to selected address", ""),
    ("copy_key", "Copy selected key / private d", ""),
    ("copy_iv", "Copy selected nonce / IV", ""),
    ("arm_selected", "Arm selected API callsite", ""),
    ("annotate", "Append algorithm comment", ""),
    ("filter", "Filter results", ""),
    ("help", "Usage / limitations", ""),
]


class Controller:
    def __init__(self):
        self.catalog = ApiCatalog()
        self.source = None
        self.scanner = None
        self.result = ScanResult()
        self.chooser = FindingsChooser(self)
        self.debugger = None
        self.handlers = []
        self.viewers = []
        self.abi_override = None
        self.manual = {}
        self.recursive_depth = 0

    def install_actions(self):
        for name, label, shortcut in ACTIONS:
            handler = Handler(self, name)
            self.handlers.append(handler)
            aid = "crypto_probe:" + name
            if ida_kernwin.register_action(
                ida_kernwin.action_desc_t(
                    aid, "Crypto Probe: " + label, handler, shortcut
                )
            ):
                ida_kernwin.attach_action_to_menu(
                    "Edit/Plugins/", aid, ida_kernwin.SETMENU_APP
                )
        ida_kernwin.msg(
            "[Crypto Probe] Offline plugin ready. Ctrl+Alt+K scan all, Ctrl+Alt+J function, Ctrl+Alt+R recursive, Ctrl+Alt+L capture.\n"
        )

    def close(self):
        if self.debugger:
            self.debugger.disarm()
        try:
            self.chooser.Close()
        except Exception:
            pass
        for name, _, _ in ACTIONS:
            ida_kernwin.unregister_action("crypto_probe:" + name)
        self.handlers.clear()

    def scan(self, current=False, recursive=False, max_depth=None):
        ida_auto.auto_wait()
        fn = None
        if current or recursive:
            fn = ida_funcs.get_func(ida_kernwin.get_screen_ea())
            if not fn:
                raise ValueError("Cursor is not in a function.")
        if recursive:
            if max_depth is None:
                max_depth = ida_kernwin.ask_long(
                    self.recursive_depth,
                    "Recursive scan depth: 0 = all reachable levels; root = level 0.\nFunction limit: 2048. Esc cancels. Known call/jump targets only.",
                )
            if max_depth is None:
                return
            if max_depth < 0:
                raise ValueError("Recursive depth must be >= 0.")
            self.recursive_depth = max_depth
        if self.debugger:
            self.debugger.disarm()
        self.source = IdaSource()
        self.source.read = read_image
        self.scanner = Scanner(self.source, self.catalog)
        addresses = None
        if fn:
            addresses = [fn.start_ea]
        ida_kernwin.show_wait_box("Crypto Probe: scanning offline…")
        try:

            def progress(index, total, ea):
                ida_kernwin.replace_wait_box(
                    "Crypto Probe: %d/%d functions · %#x" % (index, total, ea)
                )

            scope = None
            if recursive:
                def graph_progress(count, depth, ea):
                    ida_kernwin.replace_wait_box(
                        "Crypto Probe: discovering call graph · %d functions · level %d · %#x"
                        % (count, depth, ea)
                    )

                scope = collect_reachable(
                    self.source, fn.start_ea, max_depth=max_depth, progress=graph_progress
                )
                addresses = scope.addresses
            self.result = self.scanner.scan(addresses, True, progress, restrict_scope=recursive)
            if scope:
                self.result.metadata.update(scope.metadata())
                self.result.metadata["data_scope"] = "database constant/PEM fingerprints; function analysis is restricted to the recursive scope"
                self.result.diagnostics[:0] = scope.diagnostics
        finally:
            ida_kernwin.hide_wait_box()
        try:
            self.debugger = Debugger(
                self.scanner.bindings, self.on_capture, self.abi_override
            )
        except ValueError as exc:
            self.debugger = None
            self.result.diagnostics.append("Debugger capture unavailable: " + str(exc))
        self.chooser.show()
        ida_kernwin.msg(
            "[Crypto Probe] %d findings, %d API callsites. %d diagnostics.\n"
            % (
                len(self.result.findings),
                len(self.scanner.bindings),
                len(self.result.diagnostics),
            )
        )

    def on_capture(self, f):
        if not any(old is f for old in self.result.findings):
            self.result.findings.append(f)
        try:
            self.chooser.Refresh()
        except Exception:
            pass
        ida_kernwin.msg(
            "[Crypto Probe] %#x %s %s · %s\n"
            % (f.address, f.algorithm, f.mode, f.summary())
        )

    def current_binding(self):
        if not self.debugger:
            self.source = IdaSource()
            self.debugger = Debugger({}, self.on_capture, self.abi_override)
        ea = ida_kernwin.get_screen_ea()
        binding = self.debugger.binding_at(ea)
        if binding:
            return ea, binding, None
        name = target_name(ea)
        spec = self.catalog.lookup(name)
        if not spec:
            fn = ida_funcs.get_func(ea)
            if fn and fn.start_ea in self.manual:
                spec = self.manual[fn.start_ea]
                name = ida_funcs.get_func_name(fn.start_ea)
        if not spec:
            raise ValueError(
                "No binding at cursor. Scan the caller, or bind the current function first."
            )
        fn = ida_funcs.get_func(ea)
        if fn and fn.start_ea != ea:
            raise ValueError(
                "For entry capture, place the cursor and suspended IP at the function entry."
            )
        return ea, dict(spec=spec, name=name, function=ea), True

    def detail(self, f=None):
        f = f or self.chooser.chosen()
        if not f:
            raise ValueError("Select a result first.")
        v = DetailViewer()
        if v.show(f):
            self.viewers.append(v)

    def copy(self, roles):
        f = self.chooser.chosen()
        if not f:
            raise ValueError("Select a result first.")
        m = next(
            (
                m
                for role in roles
                for m in f.materials
                if m.role == role and m.hex and m.status in ("recovered", "observed")
            ),
            None,
        )
        if not m:
            raise ValueError(
                "No complete value for "
                + ", ".join(roles)
                + ". Partial/unknown bytes cannot be copied as a key."
            )
        # IDA's copy_to_clipboard is available on modern versions; fallback is an editable copy dialog.
        if hasattr(ida_kernwin, "copy_to_clipboard"):
            ida_kernwin.copy_to_clipboard(m.hex)
        else:
            ida_kernwin.ask_text(
                max(4096, len(m.hex) + 1), m.hex, "Copy " + m.role + " hex"
            )

    def export(self, draft=False):
        if draft:
            f = self.chooser.chosen()
            if not f:
                raise ValueError("Select a finding first.")
            data = crypto_draft(f)
        else:
            data = self.result.to_dict()
        path = ida_kernwin.ask_file(
            True,
            "crypto-probe-draft.json" if draft else "crypto-probe-report.json",
            "Save Crypto Probe JSON",
        )
        if path:
            Path(path).write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
            )

    def bind(self):
        fn = ida_funcs.get_func(ida_kernwin.get_screen_ea())
        if not fn:
            raise ValueError("Cursor is not in a function.")
        name = ida_funcs.get_func_name(fn.start_ea)
        template = self.manual.get(fn.start_ea)
        if template is None:
            candidate = (
                self.scanner.custom_functions.get(fn.start_ea) if self.scanner else None
            )
            template = dict(
                names=[name],
                argc=candidate["params"] if candidate else 3,
                event="direct",
                algorithm=candidate["algorithm"] if candidate else "unknown",
                mode="unknown",
                fields=(
                    [{k: v for k, v in candidate["field"].items() if k != "candidate"}]
                    if candidate
                    else [dict(role="key", arg=1, kind="bytes", length=16)]
                ),
                notes=[
                    "User-confirmed argument map; zero-based indices. Edit argc, key size and roles to match the actual function."
                ],
            )
        value = ida_kernwin.ask_text(
            32768,
            json.dumps(template, indent=2),
            "Bind arguments: review ZERO-BASED arg indices / raw-key length; optional iv/nonce fields",
        )
        if value is None:
            return
        spec = json.loads(value)
        self.catalog._validate(spec)
        spec["event"] = "direct"
        spec["names"] = [name]
        self.manual[fn.start_ea] = spec
        self.catalog.specs[normalize_name(name)] = spec
        ida_kernwin.msg(
            "[Crypto Probe] Bound %s. Re-scan callers or capture at entry; mapping is explicitly user-confirmed.\n"
            % name
        )

    def action(self, name, ctx=None):
        if name == "scan_all":
            return self.scan(False)
        if name == "scan_function":
            return self.scan(True)
        if name == "scan_recursive":
            return self.scan(True, recursive=True)
        if name == "show":
            return self.chooser.show()
        if name == "detail":
            return self.detail()
        if name == "capture":
            ea, binding, entry = self.current_binding()
            ip = ida_dbg.get_ip_val()
            if ip != ea:
                raise ValueError(
                    "Cursor is not at the suspended instruction pointer. Jump to IP before capture."
                )
            return self.debugger.capture_at(
                ea, entry_binding=binding if entry else None
            )
        if name in ("arm", "arm_selected"):
            if not self.debugger:
                raise ValueError("Run a scan first.")
            if name == "arm_selected" and not self.chooser.chosen():
                raise ValueError("Select an API result first.")
            addresses = (
                [self.chooser.chosen().address]
                if name == "arm_selected" and self.chooser.chosen()
                else None
            )
            report = self.debugger.arm(addresses)
            ida_kernwin.msg(
                "[Crypto Probe] Armed %d; skipped %d (unbound/candidate/non-call). Continue manually to capture; plugin never auto-resumes.\n"
                % (len(report["armed"]), len(report["skipped"]))
            )
            return report
        if name == "disarm":
            if self.debugger:
                self.debugger.disarm()
            return
        if name == "bind":
            return self.bind()
        if name == "export":
            return self.export(False)
        if name == "draft":
            return self.export(True)
        if name == "copy_key":
            return self.copy(("key", "d"))
        if name == "copy_iv":
            return self.copy(("nonce", "iv", "counter_block"))
        if name == "jump":
            f = self.chooser.chosen()
            if f:
                ida_kernwin.jumpto(f.address)
            return
        if name == "annotate":
            f = self.chooser.chosen()
            if not f:
                raise ValueError("Select a finding first.")
            text = "[Crypto Probe] %s/%s · %s · %s" % (
                f.algorithm,
                f.mode,
                f.confidence,
                f.source,
            )
            old = ida_bytes.get_cmt(f.address, False) or ""
            if text not in old:
                ida_bytes.set_cmt(f.address, (old + "\n" if old else "") + text, False)
            return
        if name == "filter":
            value = ida_kernwin.ask_str(
                self.chooser.filter,
                0,
                "Filter: algorithm, API, source, confidence or material role",
            )
            if value is not None:
                self.chooser.filter = value
                self.chooser.Refresh()
            return
        if name == "abi":
            default = self.abi_override or (
                self.source.arch["abi"] if self.source else "sysv64"
            )
            value = ida_kernwin.ask_str(
                default,
                0,
                "Debugger ABI: win64 / sysv64 / cdecl32 / stdcall32 / fastcall32 / aarch64 / arm32",
            )
            if value is None:
                return
            if value not in (
                "win64",
                "sysv64",
                "cdecl32",
                "stdcall32",
                "fastcall32",
                "aarch64",
                "arm32",
            ):
                raise ValueError("Unsupported ABI")
            self.abi_override = value
            if self.debugger:
                self.debugger.disarm()
                self.debugger = Debugger(
                    self.scanner.bindings if self.scanner else {},
                    self.on_capture,
                    value,
                )
            return
        if name == "help":
            ida_kernwin.info(
                "Crypto Probe runs offline.\nCtrl+Alt+K: scan database; Ctrl+Alt+J: current function; Ctrl+Alt+R: recursive function scan; Ctrl+Alt+L: capture suspended call/entry.\nRecursive depth 0 = all reachable levels, up to 2048 functions; IDA-resolved calls/tail jumps only.\nEdit > Plugins has report, bindings, ABI and debug actions.\nDouble-click a row for JSON evidence with hex addresses. Candidates are not proven algorithms/keys.\nScan then arm callsites; continue manually. Disarm removes only unmodified owned breakpoints.\nCopy crypto_probe_plugin.py and the crypto_probe folder together into IDA plugins.\nSee README_VI.md in the delivered folder for exact scope and examples."
            )
