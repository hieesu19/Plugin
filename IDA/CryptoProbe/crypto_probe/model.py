from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional
import json


def hex_address_fields(value, key=""):
    """Presentation only: preserve numeric sizes/scalars and the live model."""
    if isinstance(value, dict):
        return {k: hex_address_fields(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [hex_address_fields(v, key) for v in value]
    if type(value) is int and (
        key in ("address", "function", "ea", "callsite", "return_address", "runtime_ip", "setup_addresses")
        or key.endswith("_address")
        or key.endswith("_addresses")
    ):
        return hex(value)
    return value


@dataclass
class Evidence:
    address: int
    kind: str
    text: str


@dataclass
class Material:
    role: str
    status: str = "unresolved"
    hex: Optional[str] = None
    length: Optional[int] = None
    address: Optional[int] = None
    expression: str = ""
    source: str = ""
    notes: List[str] = field(default_factory=list)
    scalar: Optional[int] = None


@dataclass
class Finding:
    address: int
    function: int
    algorithm: str
    mode: str = "unknown"
    confidence: str = "candidate"
    source: str = "static"
    evidence: List[Evidence] = field(default_factory=list)
    materials: List[Material] = field(default_factory=list)
    api: str = ""
    direction: str = "unknown"
    notes: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, hex_addresses=False):
        data = asdict(self)
        return hex_address_fields(data) if hex_addresses else data

    def summary(self):
        return " | ".join(
            "%s:%s%s"
            % (
                m.role,
                m.status,
                (
                    ("=" + m.hex[:64])
                    if m.hex
                    else ("=" + str(m.scalar)) if m.scalar is not None else ""
                ),
            )
            for m in self.materials
        )


@dataclass
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    diagnostics: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, hex_addresses=False):
        data = dict(
            schema="crypto-probe/1",
            metadata=self.metadata,
            diagnostics=self.diagnostics,
            findings=[f.to_dict() for f in self.findings],
        )
        return hex_address_fields(data) if hex_addresses else data

    def dumps(self):
        return json.dumps(self.to_dict(hex_addresses=True), ensure_ascii=False, indent=2)


def merge_findings(findings):
    """Same address/material values merge; separate runtime key generations remain separate."""
    unique = {}
    for finding in findings:
        material = tuple(
            (m.role, m.hex, m.scalar, m.status, m.expression) for m in finding.materials
        )
        key = (
            finding.address,
            finding.algorithm,
            finding.mode,
            finding.source,
            finding.api,
            material,
        )
        old = unique.get(key)
        if old:
            seen = {(e.address, e.kind, e.text) for e in old.evidence}
            old.evidence.extend(
                e for e in finding.evidence if (e.address, e.kind, e.text) not in seen
            )
        else:
            unique[key] = finding
    return sorted(unique.values(), key=lambda f: (f.address, f.algorithm, f.source))
