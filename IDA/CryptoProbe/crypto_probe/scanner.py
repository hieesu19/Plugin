import copy
from . import __version__
from .apis import ApiCatalog, normalize_name
from .interpreter import Interpreter
from .materials import ApiDecoder, Context, collect_field
from .memory import Unknown
from .model import ScanResult, Finding, Evidence, Material, merge_findings
from .structural import structural_scan, inferred_key_parameter
from .signatures import data_scan
from .rsa import PEM_RE, parse_pem
from .forwarding import propagate_forwarded_roles
from .signatures import DEFAULT_PATTERNS


class Scanner:
    def __init__(self, source, catalog=None):
        self.source = source
        self.catalog = catalog or ApiCatalog()
        self.result = ScanResult()
        self.bindings = {}
        self.interpreters = {}
        self.custom_functions = {}

    def scan(self, addresses=None, scan_data=True, progress=None, restrict_scope=False):
        self.bindings.clear()
        self.interpreters.clear()
        self.custom_functions.clear()
        self.result = ScanResult(
            metadata=dict(
                self.source.arch,
                engine="Crypto Probe " + __version__,
                hexrays=getattr(self.source, "hexrays", False),
                coverage="bounded static analysis; unknown bytes and API success are not assumed",
                return_value_depth_limit=64,
            )
        )
        self.result.diagnostics.extend(self.catalog.errors)
        addresses = (
            list(addresses) if addresses is not None else self.source.functions()
        )
        prepared = []
        functions = {}
        structures = {}
        for index, ea in enumerate(addresses):
            if hasattr(self.source, "canceled") and self.source.canceled():
                self.result.diagnostics.append(
                    "Scan cancelled during function preparation; results are partial."
                )
                break
            if progress:
                progress(index, len(addresses), ea)
            fn = self.source.function(ea)
            prepared.append(ea)
            if fn:
                functions[ea] = fn
                fn.forwarded_crypto_key_arg = None
        table_bytes = {}
        for index, (ea, fn) in enumerate(functions.items()):
            if hasattr(self.source, "canceled") and self.source.canceled():
                self.result.diagnostics.append(
                    "Scan cancelled during pattern analysis; results are partial."
                )
                break
            if progress:
                progress(index, len(functions), ea)
            structures[ea] = structural_scan(
                fn, functions.get, getattr(self.source, "read", None)
            )
            # Link only directly referenced complete known tables to this function.
            for expr in fn.expressions():
                if expr.op != "global" or expr.value is None:
                    continue
                for algorithm, label, pattern in DEFAULT_PATTERNS:
                    if algorithm not in ("AES", "DES"):
                        continue
                    cache_key = (expr.value, len(pattern))
                    if cache_key not in table_bytes:
                        try:
                            table_bytes[cache_key] = self.source.read(*cache_key)
                        except Exception:
                            table_bytes[cache_key] = None
                    raw = table_bytes[cache_key]
                    if raw == pattern:
                        structures[ea].append(
                            Finding(
                                ea,
                                ea,
                                algorithm,
                                confidence="candidate",
                                evidence=[
                                    Evidence(
                                        expr.ea,
                                        "table_reference",
                                        label + " directly referenced by this function",
                                    ),
                                    Evidence(expr.value, "constant_table", label),
                                ],
                                notes=[
                                    "Referenced table supports an implementation candidate; mode and key remain unknown. A table reference alone does not prove encryption."
                                ],
                            )
                        )
            fn.crypto_primitive = any(
                f.algorithm
                in ("TEA", "XTEA", "XXTEA", "ChaCha-family", "Salsa-family", "RC4")
                and f.confidence != "table_match"
                for f in structures[ea]
            )
            for f in structures[ea]:
                binding = inferred_key_parameter(fn, f, functions.get)
                if binding:
                    self.custom_functions[fn.ea] = dict(
                        algorithm=f.algorithm, field=binding, params=len(fn.params)
                    )
        propagate_forwarded_roles(functions, self.custom_functions)
        for ea, spec in self.custom_functions.items():
            if spec.get("forward_depth", 0):
                functions[ea].forwarded_crypto_key_arg = spec["field"]["arg"]
        # Evaluate API callers and bounded wrapper ancestors; avoid interpreting unrelated CRT.
        edges = {
            ea: {
                x.value.get("target")
                for x in fn.expressions()
                if x.op == "call" and isinstance(x.value, dict)
            }
            for ea, fn in functions.items()
        }
        interesting = {
            ea
            for ea, fn in functions.items()
            if any(
                x.op == "call"
                and isinstance(x.value, dict)
                and self.catalog.lookup(x.value.get("name", ""))
                for x in fn.expressions()
            )
            or any(
                i.get("call") and self.catalog.lookup(i["call"]["name"])
                for i in fn.instructions
            )
            or edges[ea] & set(self.custom_functions)
        }
        # Interpret callbacks only when a known crypto function is address-taken
        # in their caller/getter chain. Unrelated CRT dispatchers still receive
        # the normal structural scan, without speculative deep interpretation.
        crypto_targets = set(self.custom_functions) | {
            ea for ea, fn in functions.items() if self.catalog.lookup(fn.name)
        }
        address_owners = {
            ea
            for ea, fn in functions.items()
            if any(
                x.op in ("global", "addr") and x.value in crypto_targets
                for x in fn.expressions()
            )
        }
        pending = set(address_owners)
        while pending:
            parents = {
                ea for ea, targets in edges.items() if targets & pending
            } - address_owners
            address_owners |= parents
            pending = parents
        interesting |= address_owners
        for _ in range(3):
            interesting |= {
                ea for ea, targets in edges.items() if targets & interesting
            }
        if len(prepared) == 1:
            interesting.update(prepared)
        for index, ea in enumerate(prepared):
            if hasattr(self.source, "canceled") and self.source.canceled():
                self.result.diagnostics.append("Scan cancelled; results are partial.")
                break
            if progress:
                progress(index, len(addresses), ea)
            fn = self.source.function(ea)
            if not fn:
                continue
            structural = structures.get(ea, [])
            self.result.findings += structural
            for f in structural:
                binding = inferred_key_parameter(fn, f, functions.get)
                if binding and fn.ea not in self.custom_functions:
                    self.custom_functions[fn.ea] = dict(
                        algorithm=f.algorithm, field=binding, params=len(fn.params)
                    )
            analysis = Interpreter(
                fn,
                self.catalog,
                getattr(self.source, "read", None),
                self.source.arch.get("endian", "little"),
                self.source.arch.get("bits", 64) // 8,
                functions.get if restrict_scope else self.source.function,
            )
            has_api = any(
                x.op == "call"
                and isinstance(x.value, dict)
                and self.catalog.lookup(x.value.get("name", ""))
                for x in fn.expressions()
            )
            if ea in interesting and (
                not getattr(fn, "crypto_primitive", False) or has_api
            ):
                analysis.run()
            self.interpreters[ea] = analysis
            self.result.findings += analysis.findings
            self.result.diagnostics += analysis.diagnostics
            for call in analysis.calls:
                spec = self.catalog.lookup(call["name"])
                if spec:
                    matching = next(
                        (
                            f
                            for f in reversed(analysis.findings)
                            if f.address == call["ea"] and f.api == call["name"]
                        ),
                        None,
                    )
                    self.bindings[call["ea"]] = dict(
                        spec=spec,
                        name=call["name"],
                        function=call.get("function", fn.ea),
                        args=call["args"],
                        static_values=call["values"],
                        hint=matching.metadata if matching else {},
                    )
            # Even without Hex-Rays, actual call locations/API names remain discoverable.
            for ins in fn.instructions:
                call = ins.get("call")
                spec = self.catalog.lookup(call["name"]) if call else None
                if spec and ins["ea"] not in self.bindings:
                    values = [
                        Unknown("Hex-Rays/argument data flow unavailable")
                    ] * spec["argc"]
                    f, _ = ApiDecoder(
                        pointer_size=self.source.arch.get("bits", 64) // 8
                    ).decode(call["name"], spec, values, analysis.memory, ins["ea"], ea)
                    f.notes.append(
                        "Disassembly-only API location; use debugger capture for argument bytes."
                    )
                    self.result.findings.append(f)
                    self.bindings[ins["ea"]] = dict(
                        spec=spec,
                        name=call["name"],
                        function=ea,
                        args=[],
                        static_values=values,
                    )
        # Give custom primitive callers key candidates based on structural parameter use.
        for ea, analysis in self.interpreters.items():
            for call in analysis.calls:
                spec = self.custom_functions.get(call.get("target"))
                if not spec:
                    continue
                api = dict(
                    names=[call["name"] or "structural_primitive"],
                    argc=spec["params"],
                    event="direct",
                    algorithm=spec["algorithm"],
                    mode="unknown",
                    fields=[
                        {k: v for k, v in spec["field"].items() if k != "candidate"}
                    ],
                )
                values = call["values"] + [Unknown("argument missing")] * max(
                    0, spec["params"] - len(call["values"])
                )
                # Recovered bytes must be read at the call's state, not function-end memory.
                f = Finding(
                    call["ea"],
                    call.get("function", ea),
                    spec["algorithm"],
                    confidence="candidate",
                    evidence=[
                        Evidence(
                            call["ea"],
                            "parameter_role",
                            "Possible four-word key argument inferred from primitive accesses; forwarded wrapper levels: "
                            + str(spec.get("forward_depth", 0)),
                        )
                    ],
                    metadata=dict(
                        forwarded_levels=spec.get("forward_depth", 0),
                        primitive_address=spec.get("primitive", call.get("target")),
                        argument_providers=call.get("argument_providers", []),
                        resolved_indirect=call.get("resolved_indirect", False),
                    ),
                    materials=[
                        Material(
                            "key",
                            expression=str(values[spec["field"]["arg"]]),
                            length=16,
                            source="static",
                            notes=[
                                "Candidate argument role. Confirm the key binding before treating this as a decrypt configuration."
                            ],
                        )
                    ],
                )
                candidate = collect_field(
                    api["fields"][0],
                    values,
                    call["memory"],
                    Context(),
                    "static",
                    call["ea"],
                )
                candidate.notes.append(
                    "Structural parameter-role candidate, not a library API contract. Confirm manually."
                )
                f.materials = [candidate]
                self.result.findings.append(f)
                self.bindings.setdefault(
                    call["ea"],
                    dict(
                        spec=api,
                        name=call["name"] or "structural_primitive",
                        function=call.get("function", ea),
                        args=call["args"],
                        static_values=values,
                        candidate=True,
                    ),
                )
        if scan_data:
            carry = b""
            end = None
            seen_pem = set()
            for address, raw in self.source.segments():
                if hasattr(self.source, "canceled") and self.source.canceled():
                    self.result.diagnostics.append(
                        "Data scan cancelled; results are partial."
                    )
                    break
                combined = (carry if end == address else b"") + raw
                start = address - (len(carry) if end == address else 0)
                self.result.findings += data_scan(combined, start)
                for m in PEM_RE.finditer(combined):
                    at = start + m.start()
                    if at in seen_pem:
                        continue
                    seen_pem.add(at)
                    try:
                        parsed = parse_pem(m[0])
                    except ValueError:
                        continue
                    material = [
                        Material(
                            "pem",
                            status="recovered",
                            hex=m[0].hex(),
                            length=len(m[0]),
                            address=at,
                            source="static",
                            expression=parsed["pem"],
                        )
                    ]
                    for role, n in parsed["numbers"].items():
                        hx = format(n, "x")
                        hx = ("0" + hx) if len(hx) % 2 else hx
                        material.append(
                            Material(
                                role,
                                "recovered",
                                hex=hx,
                                length=len(hx) // 2,
                                source="static",
                            )
                        )
                    self.result.findings.append(
                        Finding(
                            at,
                            at,
                            parsed["algorithm"],
                            confidence="format_match",
                            materials=material,
                            evidence=[Evidence(at, "pem", parsed["label"])],
                            notes=(
                                [
                                    "Encrypted PEM requires passphrase; private numbers were not extracted."
                                ]
                                if parsed.get("encrypted")
                                else [
                                    "RSA PEM material; encryption padding/OAEP hashes are not stored in this PEM."
                                ]
                            ),
                        )
                    )
                carry = combined[-32768:]
                end = address + len(raw)
        self.result.findings = merge_findings(self.result.findings)
        self.result.diagnostics = list(dict.fromkeys(self.result.diagnostics))
        self.result.metadata.update(
            functions_scanned=len(self.interpreters),
            api_callsites=len(self.bindings),
            findings=len(self.result.findings),
        )
        if getattr(self.source, "errors", None):
            self.result.diagnostics.extend(
                "%#x: decompile/lift failed: %s" % (ea, error)
                for ea, error in self.source.errors.items()
            )
        return self.result
