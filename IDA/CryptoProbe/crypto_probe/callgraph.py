"""Collect a function's reachable code before decompiling; cycles are visited once."""

from collections import deque
from dataclasses import dataclass, field


@dataclass
class RecursiveScope:
    root: int
    addresses: list = field(default_factory=list)
    depths: dict = field(default_factory=dict)
    diagnostics: list = field(default_factory=list)
    unresolved_calls: int = 0
    truncated: bool = False
    max_depth: int = 0
    max_functions: int = 2048

    def metadata(self):
        return {
            "scan_scope": "recursive",
            "root_address": self.root,
            "max_depth": self.max_depth,
            "max_functions": self.max_functions,
            "deepest_level": max(self.depths.values(), default=0),
            "function_depths": {hex(ea): depth for ea, depth in self.depths.items()},
            "known_graph_complete": not self.truncated,
            "unresolved_indirect_calls": self.unresolved_calls,
            "graph_edges": "IDA-resolved calls, inter-function jumps and address-taken code targets",
        }


def collect_reachable(source, root, max_depth=0, max_functions=2048, progress=None):
    """Depth 0 means no depth cap. Discovery never asks for decompiled IR.

    source.function_start normalizes a target to its defined code function.
    source.callees returns (known code-function targets, unresolved call count).
    External imports are leaves, not extra functions to decompile.
    """
    if type(max_depth) is not int or max_depth < 0:
        raise ValueError("Recursive depth must be >= 0 (0 = all reachable levels).")
    if type(max_functions) is not int or max_functions < 1:
        raise ValueError("Recursive function limit must be >= 1.")
    root = source.function_start(root)
    if root is None:
        raise ValueError("Recursive root is not a defined code function.")
    scope = RecursiveScope(root, max_depth=max_depth, max_functions=max_functions)
    scope.addresses.append(root)
    scope.depths[root] = 0
    queue = deque([root])
    depth_limited = budget_limited = False
    while queue:
        if hasattr(source, "canceled") and source.canceled():
            scope.truncated = True
            scope.diagnostics.append("Recursive discovery cancelled; scope is partial.")
            break
        ea = queue.popleft()
        depth = scope.depths[ea]
        if progress:
            progress(len(scope.addresses), depth, ea)
        targets, unresolved = source.callees(ea)
        scope.unresolved_calls += unresolved
        for target in sorted(set(targets)):
            callee = source.function_start(target)
            if callee is None or callee in scope.depths:
                continue
            if max_depth and depth >= max_depth:
                depth_limited = True
                continue
            if len(scope.addresses) >= max_functions:
                budget_limited = True
                continue
            scope.addresses.append(callee)
            scope.depths[callee] = depth + 1
            queue.append(callee)
    if depth_limited:
        scope.truncated = True
        scope.diagnostics.append(
            "Recursive depth limit %d reached; deeper functions were not scanned."
            % max_depth
        )
    if budget_limited:
        scope.truncated = True
        scope.diagnostics.append(
            "Recursive function limit %d reached; scope is partial." % max_functions
        )
    if not scope.truncated and hasattr(source, "canceled") and source.canceled():
        scope.truncated = True
        scope.diagnostics.append("Recursive discovery cancelled; scope is partial.")
    if scope.unresolved_calls:
        scope.diagnostics.append(
            "%d indirect call(s) have no resolved code target; add IDA call xrefs or scan/bind their targets explicitly."
            % scope.unresolved_calls
        )
    return scope
