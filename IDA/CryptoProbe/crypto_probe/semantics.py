"""Small, read-only IR normalization. Never patches the IDB or executes code."""

from dataclasses import replace
from itertools import islice
from .ir import Expr, Stmt, FunctionIR


def helper_template(fn, lookup=None, path=()):
    """Straight-line return expression, including local compiler temporaries.

    Loops, branches, writes through pointers, unknown calls and multiple returns
    are deliberately excluded. Loads are retained as expressions, not evaluated.
    """
    env = {}
    result = []
    count = [0]

    def subst(e):
        if e.op == "var" and e.value in env:
            return env[e.value]
        return replace(e, args=[subst(a) for a in e.args])

    def walk(body):
        for s in body:
            count[0] += 1
            if count[0] > 24:
                return False
            if s.op == "block":
                if not walk(s.body):
                    return False
            elif (
                s.op == "expr"
                and s.expr
                and s.expr.op == "assign"
                and s.expr.args[0].op == "var"
            ):
                lhs, rhs = s.expr.args
                if lhs.value in fn.params:
                    return False
                env[lhs.value] = subst(rhs)
            elif s.op == "return" and s.expr:
                result.append(subst(s.expr))
            else:
                return False
        return True

    if not walk(fn.body) or len(result) != 1:
        return None
    e = result[0]
    nodes = list(islice(e.walk(), 161))
    if len(nodes) > 160 or any(
        n.op.startswith("assign")
        or n.op in ("preinc", "postinc", "predec", "postdec", "unknown")
        for n in nodes
    ):
        return None
    if any(n.op == "var" and n.value not in fn.params for n in nodes):
        return None
    for node in nodes:
        if node.op != "call":
            continue
        target = node.value.get("target") if isinstance(node.value, dict) else None
        if not lookup or not target or target in path + (fn.ea,) or len(path) >= 3:
            return None
        child = lookup(target)
        if child is None or helper_template(child, lookup, path + (fn.ea,)) is None:
            return None
    return e


def normalized_function(fn, lookup=None):
    """Expand small read-only helpers (depth 3), fold arithmetic constants and
    multiplication by powers of two. Bound total expansion to 12000 nodes.
    """
    helper_eas = set()
    templates = {}
    budget = [12000]

    def norm(e, substitutions=None, path=()):
        budget[0] -= 1
        if budget[0] <= 0:
            return e
        if e.op == "var" and substitutions and e.value in substitutions:
            return substitutions[e.value]
        args = [norm(a, substitutions, path) for a in e.args]
        out = replace(e, args=args)
        if (
            out.op == "call"
            and isinstance(out.value, dict)
            and lookup
            and len(path) < 3
        ):
            target = out.value.get("target")
            if target and target not in path and target != fn.ea:
                if target not in templates:
                    callee = lookup(target)
                    templates[target] = (
                        (callee, helper_template(callee, lookup))
                        if callee
                        else (None, None)
                    )
                callee, template = templates[target]
                if template is not None and len(args) == len(callee.params):
                    helper_eas.add(target)
                    return norm(
                        template, dict(zip(callee.params, args)), path + (target,)
                    )
        if (
            out.op in ("add", "sub", "mul", "and", "or", "xor")
            and len(args) == 2
            and all(a.op == "num" for a in args)
        ):
            a, b = (x.value for x in args)
            v = {
                "add": lambda: a + b,
                "sub": lambda: a - b,
                "mul": lambda: a * b,
                "and": lambda: a & b,
                "or": lambda: a | b,
                "xor": lambda: a ^ b,
            }[out.op]()
            if 0 < out.bits <= 128:
                v &= (1 << out.bits) - 1
            return Expr("num", value=v, bits=out.bits, ea=out.ea)
        if out.op == "mul" and len(args) == 2:
            for i in (0, 1):
                c = args[i]
                if c.op == "num" and c.value > 1 and c.value & (c.value - 1) == 0:
                    return replace(
                        out,
                        op="shl",
                        args=[
                            args[1 - i],
                            Expr(
                                "num", value=c.value.bit_length() - 1, bits=32, ea=c.ea
                            ),
                        ],
                    )
        return out

    def statements(body):
        return [
            replace(
                s,
                expr=norm(s.expr) if s.expr else None,
                init=norm(s.init) if s.init else None,
                step=norm(s.step) if s.step else None,
                body=statements(s.body),
                other=statements(s.other),
            )
            for s in body
        ]

    normalized = replace(fn, body=statements(fn.body))
    return normalized, helper_eas


def value_walk(node):
    """Visit data-value arithmetic, excluding pointer/index arithmetic."""
    yield node
    if node.op in ("index", "load", "member"):
        return
    for arg in node.args:
        yield from value_walk(arg)


def rotate_pattern(e, width):
    """(x << n) OR/XOR/add (x >> (width-n)) with identical source."""
    if e.op in ("rol", "ror") and len(e.args) == 2 and e.args[1].op == "num":
        n = e.args[1].value % width
        return e.args[0], n if e.op == "rol" else (width - n) % width
    if e.op not in ("or", "xor", "add") or len(e.args) != 2:
        return None
    a, b = e.args
    if a.op == "shr":
        a, b = b, a
    if (
        a.op == "shl"
        and b.op == "shr"
        and len(a.args) == len(b.args) == 2
        and a.args[1].op == b.args[1].op == "num"
    ):
        n, m = a.args[1].value, b.args[1].value
        if (
            0 < n < width
            and n + m == width
            and a.args[0].display() == b.args[0].display()
        ):
            return a.args[0], n
    return None
