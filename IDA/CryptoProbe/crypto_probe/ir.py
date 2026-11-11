"""Small structured IR; no IDA imports, also usable for replay tests."""

from dataclasses import dataclass, field
from typing import Any, List, Dict


@dataclass
class Expr:
    op: str
    args: List["Expr"] = field(default_factory=list)
    value: Any = None
    bits: int = 0
    ea: int = 0
    text: str = ""
    scale: int = 1
    callee: "Expr" = None

    def walk(self):
        yield self
        if self.callee is not None:
            yield from self.callee.walk()
        for a in self.args:
            yield from a.walk()

    def display(self):
        if self.text:
            return self.text
        if self.op == "num":
            return hex(self.value)
        if self.op in ("var", "global", "addr", "string"):
            return str(self.value)
        return "%s(%s)" % (self.op, ", ".join(a.display() for a in self.args))


@dataclass
class Stmt:
    op: str
    expr: Expr = None
    body: List["Stmt"] = field(default_factory=list)
    other: List["Stmt"] = field(default_factory=list)
    init: Expr = None
    step: Expr = None
    ea: int = 0

    def walk(self):
        for x in (self.expr, self.init, self.step):
            if x:
                yield from x.walk()
        for s in self.body + self.other:
            yield from s.walk()


@dataclass
class FunctionIR:
    ea: int
    name: str
    body: List[Stmt]
    params: List[str] = field(default_factory=list)
    varinfo: Dict[str, dict] = field(default_factory=dict)
    instructions: List[dict] = field(default_factory=list)

    def expressions(self):
        for statement in self.body:
            yield from statement.walk()


def num(n, bits=32, ea=0):
    return Expr("num", value=n, bits=bits, ea=ea)


def var(name, bits=32):
    return Expr("var", value=name, bits=bits)
