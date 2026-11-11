"""Role summaries for thin argument-forwarding wrappers (no deep emulation)."""

from collections import defaultdict, deque


def parameter_pointer(e, fn):
    if e.op == "cast" and e.args:
        return parameter_pointer(e.args[0], fn)
    if e.op == "var" and e.value in fn.params:
        return fn.params.index(e.value), 0
    if (
        e.op in ("ptradd", "ptrsub", "add", "sub")
        and len(e.args) == 2
        and e.args[1].op == "num"
    ):
        parent = parameter_pointer(e.args[0], fn)
        if parent:
            sign = -1 if e.op in ("ptrsub", "sub") else 1
            return parent[0], parent[1] + sign * e.args[1].value * (
                e.scale if e.op.startswith("ptr") else 1
            )
    return None


def propagate_forwarded_roles(functions, specs):
    """Promote a role through sole-call wrappers without changing primitives.

    Reject branches/loops, buffer writes, other calls and re-assigned parameter
    expressions. Offsets are deliberately not guessed. A key at wrapper entry
    is a candidate only when it is forwarded unchanged to the known role.
    """
    parents = defaultdict(list)
    for fn in functions.values():
        exprs = list(fn.expressions())
        calls = [e for e in exprs if e.op == "call" and isinstance(e.value, dict)]

        def straight(body):
            return all(
                s.op in ("block", "expr", "return") and straight(s.body) and not s.other
                for s in body
            )

        if len(calls) != 1 or not straight(fn.body):
            continue
        if any(
            e.op in ("preinc", "postinc", "predec", "postdec")
            or e.op.startswith("assign")
            for e in exprs
        ):
            continue
        call = calls[0]
        parents[call.value.get("target")].append((fn, call))
    work = deque(specs)
    seen = set(specs)
    while work:
        target = work.popleft()
        spec = specs[target]
        for fn, call in parents.get(target, []):
            if fn.ea in seen:
                continue
            index = spec["field"]["arg"]
            if index >= len(call.args):
                continue
            mapped = parameter_pointer(call.args[index], fn)
            if mapped is None or mapped[1] != 0:
                continue
            fields = dict(spec["field"], arg=mapped[0])
            specs[fn.ea] = dict(
                algorithm=spec["algorithm"],
                field=fields,
                params=len(fn.params),
                forward_depth=spec.get("forward_depth", 0) + 1,
                primitive=spec.get("primitive", target),
            )
            seen.add(fn.ea)
            work.append(fn.ea)
    return specs
