import copy
from dataclasses import dataclass, field
from .model import Material, Finding, Evidence
from .memory import Pointer, Tagged, Unknown
from .apis import cipher_descriptor, parse_cipher_string, normalize_name
from .rsa import parse_blob

MAX_CAPTURE = 65536


def pointer(value):
    if isinstance(value, Pointer):
        return value
    if isinstance(value, int) and value > 0:
        return Pointer("image", value)
    return None


def read_bytes(memory, value, length):
    if (
        isinstance(value, Tagged)
        and value.kind == "literal_bytes"
        and isinstance(length, int)
        and 0 <= length <= MAX_CAPTURE
    ):
        raw = value.value + b"\0"
        return raw[:length] if length <= len(raw) else None
    if (
        isinstance(value, Tagged)
        and value.kind == "string"
        and isinstance(length, int)
        and 0 <= length <= MAX_CAPTURE
    ):
        try:
            raw = value.value.encode("ascii") + b"\0"
        except UnicodeError:
            return None
        return raw[:length] if length <= len(raw) else None
    p = pointer(value)
    if not p or not isinstance(length, int) or not 0 <= length <= MAX_CAPTURE:
        return None
    data = memory.bytes(p, length)
    return (
        bytes(data) if data is not None and all(b is not None for b in data) else None
    )


def read_string(memory, value, wide=False, limit=512):
    if isinstance(value, Tagged) and value.kind == "literal_bytes":
        try:
            return value.value.split(b"\0", 1)[0].decode("utf-8")
        except UnicodeError:
            return None
    if isinstance(value, Tagged) and value.kind in ("string", "wide_string"):
        return str(value.value)
    if isinstance(value, str):
        return value
    p = pointer(value)
    if not p:
        return None
    result = []
    step = 2 if wide else 1
    for off in range(0, limit, step):
        raw = read_bytes(memory, p.add(off), step)
        if raw is None:
            return None
        if raw == b"\x00" * step:
            try:
                return bytes(result).decode("utf-16-le" if wide else "utf-8")
            except UnicodeError:
                return None
        result.extend(raw)
    return None


@dataclass
class Context:
    algorithm: str = "unknown"
    mode: str = "unknown"
    attributes: dict = field(default_factory=dict)
    materials: dict = field(default_factory=dict)

    def clone(self):
        return copy.deepcopy(self)


class Contexts:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.setdefault(key, Context())

    def clone(self):
        c = Contexts()
        c.values = copy.deepcopy(self.values)
        return c

    def merge(self, other):
        for key in set(self.values) | set(other.values):
            a = self.values.get(key)
            b = other.values.get(key)
            if a is None or b is None:
                self.values.pop(key, None)
                continue
            if a.algorithm != b.algorithm:
                a.algorithm = "unknown"
            if a.mode != b.mode:
                a.mode = "unknown"
            a.attributes = {
                k: v for k, v in a.attributes.items() if b.attributes.get(k) == v
            }
            a.materials = {
                k: v for k, v in a.materials.items() if b.materials.get(k) == v
            }


def context_key(value):
    if isinstance(value, Pointer):
        return value.label()
    if isinstance(value, Tagged):
        return (value.kind, str(value.value))
    if isinstance(value, int) and value:
        return ("handle", value)
    return None


def number_material(role, n, source):
    h = hex(n)[2:]
    h = ("0" + h) if len(h) % 2 else h
    return Material(role, status="recovered", hex=h, length=len(h) // 2, source=source)


def collect_field(profile, values, memory, context, source, ea):
    index = profile["arg"]
    v = values[index] if index < len(values) else Unknown("argument missing")
    role = profile["role"]
    kind = profile.get("kind", "bytes")
    m = Material(
        role,
        source=source,
        expression=v.label() if isinstance(v, Pointer) else str(v),
        address=(
            v.address()
            if isinstance(v, Pointer)
            else v if isinstance(v, int) and kind not in ("scalar",) else None
        ),
    )
    if kind == "scalar":
        if isinstance(v, int):
            m.scalar = v
            m.status = "observed" if source == "debug" else "recovered"
        return m
    if kind in ("pointer", "opaque"):
        m.status = "pointer_only" if pointer(v) else "unresolved"
        return m
    if kind in ("cstring", "utf16"):
        s = read_string(memory, v, kind == "utf16")
        if s is not None:
            m.status = "observed" if source == "debug" else "recovered"
            m.expression = s
            m.hex = s.encode("utf-16-le" if kind == "utf16" else "utf-8").hex()
            m.length = len(bytes.fromhex(m.hex))
        return m
    length = profile.get("length")
    if profile.get("length_arg") is not None:
        li = profile["length_arg"]
        length = values[li] if li < len(values) else None
        divisor = profile.get("length_divisor", 1)
        if isinstance(length, int):
            length = length // divisor if length % divisor == 0 else None
    if profile.get("length_from"):
        length = context.attributes.get(profile["length_from"])
    if not isinstance(length, int):
        m.notes.append("Length unresolved; no buffer-size guess.")
        return m
    m.length = length
    if length == 0:
        m.status = "not_applicable"
        return m
    if not 0 < length <= MAX_CAPTURE:
        m.status = "invalid_length"
        m.notes.append("Length outside capture limit.")
        return m
    raw = read_bytes(memory, v, length)
    if raw is not None:
        m.hex = raw.hex()
        m.status = "observed" if source == "debug" else "recovered"
    else:
        p = pointer(v)
        partial = memory.bytes(p, length) if p else None
        if partial is not None:
            known = sum(b is not None for b in partial)
            m.notes.append(
                "%d/%d bytes known; partial bytes are not exported as a key."
                % (known, length)
            )
            if known:
                m.status = "partial"
    return m


class ApiDecoder:
    def __init__(self, contexts=None, pointer_size=8):
        self.contexts = contexts or Contexts()
        self.pointer_size = pointer_size

    def decode(
        self,
        name,
        spec,
        values,
        memory,
        ea,
        function,
        source="static",
        conditional=False,
    ):
        name = normalize_name(name)
        event = spec["event"]
        key = (
            context_key(values[spec["context_arg"]])
            if spec.get("context_arg") is not None and spec["context_arg"] < len(values)
            else None
        )
        context = self.contexts.get(key) if key is not None else Context()
        # A provider creates independent key handles. Do not store key bytes on the provider.
        if event in ("cng_key", "cng_import", "capi_import"):
            context = context.clone()
        if spec.get("algorithm", "unknown") != "unknown":
            context.algorithm = spec["algorithm"]
        if spec.get("mode", "unknown") != "unknown":
            context.mode = spec["mode"]
        for attr in (
            "cfb_segment_bits",
            "tag_length",
            "layout",
            "key_length",
            "iv_length",
        ):
            if spec.get(attr) is not None:
                context.attributes[attr] = spec[attr]
        if event == "evp_init":
            cipher = (
                values[spec["cipher_arg"]] if spec["cipher_arg"] < len(values) else None
            )
            desc = (
                cipher.value
                if isinstance(cipher, Tagged) and cipher.kind == "cipher"
                else None
            )
            if desc:
                context.algorithm = desc["algorithm"]
                context.mode = desc["mode"]
                context.attributes.update(desc)
            if name.endswith("_ex2") and values[-1] != 0:
                context.attributes.pop("key_length", None)
                context.attributes.pop("iv_length", None)
                context.attributes["params_unparsed"] = True
        if event == "setkey":
            if spec.get("cipher_id_arg") is not None:
                cid = values[spec["cipher_id_arg"]]
                if cid == 2:
                    context.algorithm = "AES"
                else:
                    context.algorithm = "unknown"
            if spec.get("key_bits_arg") is not None:
                bits = values[spec["key_bits_arg"]]
                if isinstance(bits, int) and bits in (128, 192, 256):
                    context.attributes["key_length"] = bits // 8
        if context.algorithm == "AES" and not context.attributes.get("params_unparsed"):
            context.attributes.setdefault("iv_length", 16)
        elif context.algorithm == "DES":
            context.attributes.setdefault("iv_length", 8)
        elif context.algorithm == "RC4":
            context.attributes["iv_length"] = 0
        if context.mode == "ECB":
            context.attributes["iv_length"] = 0
        direction = spec.get("direction", "unknown")
        enc = spec.get("enc_arg")
        if enc is not None and enc < len(values) and values[enc] in (0, 1):
            direction = "encrypt" if values[enc] else "decrypt"
        elif "decrypt" in name.lower():
            direction = "decrypt"
        elif "encrypt" in name.lower():
            direction = "encrypt"
        fields = [
            collect_field(p, values, memory, context, source, ea)
            for p in spec.get("fields", [])
        ]
        byrole = {m.role: m for m in fields}
        notes = list(spec.get("notes", []))
        if name.startswith("crypto_aead_") and spec.get("tag_length"):
            n = spec["tag_length"]
            if (
                direction == "decrypt"
                and len(values) > 4
                and isinstance(values[4], int)
                and n <= values[4] <= MAX_CAPTURE
            ):
                p = pointer(values[3])
                if p:
                    fields.append(
                        collect_field(
                            dict(role="tag", arg=0, length=n),
                            [p.add(values[4] - n)],
                            memory,
                            context,
                            source,
                            ea,
                        )
                    )
            elif direction == "encrypt":
                fields.append(
                    Material(
                        "tag",
                        "output_pending",
                        length=n,
                        source=source,
                        notes=[
                            "libsodium combined AEAD: tag follows ciphertext; read after successful return."
                        ],
                    )
                )
        if spec.get("output_fields"):
            for m in fields:
                if m.role in spec["output_fields"]:
                    m.hex = None
                    m.status = "output_pending"
                    m.notes.append(
                        "Output buffer: read after successful return, not before the call."
                    )
        if event == "evp_ctrl":
            cmd = values[1] if len(values) > 1 else None
            n = values[2] if len(values) > 2 else None
            if cmd == 9 and isinstance(n, int) and 1 <= n <= MAX_CAPTURE:
                context.attributes["iv_length"] = n
            elif cmd == 0x11 and isinstance(n, int) and 0 < n <= 64:
                role = "tag"
                m = collect_field(
                    dict(role=role, arg=3, length=n),
                    values,
                    memory,
                    context,
                    source,
                    ea,
                )
                fields.append(m)
            elif cmd == 0x10:
                notes.append(
                    "EVP GET_TAG is output; capture after return to avoid stale tag bytes."
                )
        if event == "set_padding" and isinstance(values[1], int):
            context.attributes["padding"] = "pkcs7" if values[1] else "none"
        if (
            event == "set_key_length"
            and isinstance(values[1], int)
            and 1 <= values[1] <= MAX_CAPTURE
        ):
            context.attributes["key_length"] = values[1]
        if event == "cng_open":
            s = byrole.get("algorithm_name")
            alg = s.expression.upper() if s and s.hex else ""
            context.algorithm = {
                "AES": "AES",
                "DES": "DES",
                "RC4": "RC4",
                "RSA": "RSA",
                "3DES": "3DES",
                "CHACHA20_POLY1305": "ChaCha20-Poly1305",
            }.get(alg, "unknown")
            if context.algorithm in ("AES", "DES"):
                context.attributes["iv_length"] = (
                    16 if context.algorithm == "AES" else 8
                )
        if event == "cng_property":
            prop = byrole.get("property_name")
            raw = byrole.get("property_data")
            if prop and prop.expression == "ChainingMode" and raw and raw.hex:
                try:
                    mode = (
                        bytes.fromhex(raw.hex)
                        .decode("utf-16-le")
                        .rstrip("\x00")
                        .replace("ChainingMode", "")
                        .upper()
                    )
                except UnicodeError:
                    mode = "unknown"
                if mode in ("ECB", "CBC", "CFB", "OFB", "GCM", "CCM"):
                    context.mode = mode
                    context.attributes["mode_source"] = "BCryptSetProperty"
        if event in ("cng_import", "capi_import"):
            blob = byrole.get("key_blob")
            parsed = parse_blob(bytes.fromhex(blob.hex)) if blob and blob.hex else None
            if parsed:
                if parsed["algorithm"] != "unknown":
                    context.algorithm = parsed["algorithm"]
                if "key" in parsed:
                    fields.append(
                        Material(
                            "key",
                            status="observed" if source == "debug" else "recovered",
                            hex=parsed["key"].hex(),
                            length=len(parsed["key"]),
                            source=source,
                            notes=["Parsed " + parsed["format"]],
                        )
                    )
                for role, n in parsed.get("numbers", {}).items():
                    fields.append(number_material(role, n, source))
                if parsed.get("d_derived"):
                    notes.append(
                        "RSA d derived from checked p/q using modular inverse; not read directly."
                    )
                context.attributes["blob_format"] = parsed["format"]
                if context.algorithm in ("AES", "DES", "3DES"):
                    context.attributes["iv_length"] = (
                        16 if context.algorithm == "AES" else 8
                    )
            elif blob:
                notes.append(
                    "Blob format not recognized or incomplete; blob bytes are not relabeled as a raw key."
                )
        if event == "capi_property":
            param = values[1]
            data = values[2]
            if param == 1:
                length = context.attributes.get("iv_length")
                fields.append(
                    collect_field(
                        dict(role="iv", arg=2, length_from="iv_length"),
                        values,
                        memory,
                        context,
                        source,
                        ea,
                    )
                )
            elif param == 4:
                raw = read_bytes(memory, data, 4)
                if raw:
                    context.mode = {
                        1: "CBC",
                        2: "ECB",
                        3: "OFB",
                        4: "CFB",
                        5: "CTS",
                    }.get(int.from_bytes(raw, "little"), "unknown")
            elif param == 3:
                raw = read_bytes(memory, data, 4)
                if raw:
                    context.attributes["padding_constant"] = int.from_bytes(
                        raw, "little"
                    )
        if event == "cng_use":
            p = pointer(values[3]) if len(values) > 3 else None
            if p and context.mode in ("GCM", "CCM", "unknown"):
                authenticated = self.auth_info(memory, p, source)
                if any(m.role == "nonce" for m in authenticated):
                    fields = [
                        m
                        for m in fields
                        if not (m.role == "iv" and m.status == "not_applicable")
                    ]
                if direction == "encrypt":
                    for m in authenticated:
                        if m.role == "tag":
                            m.hex = None
                            m.status = "output_pending"
                            m.notes.append(
                                "Authentication tag output: only read after successful encryption return."
                            )
                fields.extend(authenticated)
                if any(m.role == "nonce" for m in fields) and context.mode == "unknown":
                    notes.append(
                        "Authenticated-mode struct found; GCM vs CCM unresolved without chaining-mode evidence."
                    )
        if event == "rsa_use" or event == "rsa_padding":
            pad = next((m.scalar for m in fields if m.role == "rsa_padding"), None)
            if pad is not None:
                context.attributes["rsa_padding"] = {
                    1: "PKCS1v1.5",
                    3: "none",
                    4: "OAEP",
                }.get(pad, "constant " + str(pad))
            if pad == 4:
                notes.append(
                    "OAEP hash/MGF1 hash must come from API contract or context setters; PEM does not specify them."
                )
        if (
            event == "rsa_hash"
            and len(values) > 1
            and isinstance(values[1], Tagged)
            and values[1].kind == "hash"
        ):
            context.attributes["mgf1_hash" if "mgf1" in name else "oaep_hash"] = values[
                1
            ].value
        if event == "rsa_setkey":
            for m in fields:
                bctx = self.contexts.values.get(
                    context_key(
                        values[
                            next(
                                p["arg"] for p in spec["fields"] if p["role"] == m.role
                            )
                        ]
                    )
                )
                if bctx and bctx.materials.get("bignum_bytes"):
                    recovered = copy.deepcopy(bctx.materials["bignum_bytes"])
                    recovered.role = m.role
                    m.hex = recovered.hex
                    m.length = recovered.length
                    m.status = recovered.status
                    m.notes.append(
                        "Role assigned by RSA_set0_key argument; BIGNUM bytes tracked from BN_bin2bn."
                    )
                elif (
                    bctx
                    and bctx.materials.get("word")
                    and isinstance(bctx.materials["word"].scalar, int)
                ):
                    recovered = number_material(
                        m.role, bctx.materials["word"].scalar, source
                    )
                    m.hex = recovered.hex
                    m.length = recovered.length
                    m.status = recovered.status
                    m.notes.append(
                        "BIGNUM scalar tracked from BN_set_word; role assigned by RSA_set0_key."
                    )
        setup = list(context.attributes.get("setup_addresses", []))
        if event not in (
            "destroy_context",
            "cng_use",
            "capi_use",
            "context_use",
            "rsa_use",
            "direct",
        ):
            if ea not in setup:
                setup.append(ea)
            context.attributes["setup_addresses"] = setup[-32:]
        for m in fields:
            if m.role in (
                "key",
                "iv",
                "nonce",
                "counter_block",
                "counter",
                "n",
                "e",
                "d",
                "oaep_label",
                "tag",
            ) and m.status in ("recovered", "observed"):
                # NULL key/IV in EVP init means retain old state, not a new zero key.
                context.materials[m.role] = copy.deepcopy(m)
        if event == "destroy_context" and key is not None:
            self.contexts.values.pop(key, None)
        if event in ("bignum_import", "bignum_word"):
            for m in fields:
                context.materials[m.role] = copy.deepcopy(m)
        direct = {m.role for m in fields}
        inherited = [
            copy.deepcopy(m)
            for role, m in context.materials.items()
            if role not in direct
        ]
        for m in inherited:
            m.notes.append(
                "From matching context/handle setup; inspect setup evidence."
            )
        if context.algorithm == "ChaCha20" and context.attributes.get(
            "layout", ""
        ).startswith("OpenSSL ChaCha20"):
            iv = next(
                (
                    m
                    for m in fields + inherited
                    if m.role == "iv" and m.hex and m.length == 16
                ),
                None,
            )
            if iv:
                raw = bytes.fromhex(iv.hex)
                fields.append(
                    Material(
                        "counter",
                        iv.status,
                        scalar=int.from_bytes(raw[:8], "little"),
                        source=source,
                        notes=[
                            "OpenSSL original ChaCha20: first 8 IV bytes are LE64 counter."
                        ],
                    )
                )
                fields.append(
                    Material(
                        "nonce",
                        iv.status,
                        hex=raw[8:].hex(),
                        length=8,
                        source=source,
                        notes=[
                            "OpenSSL original ChaCha20: final 8 IV bytes are nonce."
                        ],
                    )
                )
        else:
            for m in fields + inherited:
                if m.role == "iv" and (
                    context.mode in ("GCM", "CCM")
                    or context.algorithm in ("ChaCha20-Poly1305", "XChaCha20-Poly1305")
                ):
                    m.role = "nonce"
        if conditional:
            notes.append(
                "Static path condition unresolved: these are possible call arguments, not a proven executed path."
            )
        if any(isinstance(v, Unknown) for v in values):
            notes.append(
                "Some arguments unresolved; no implicit memory/context layout guessing."
            )
        evidence = [Evidence(ea, "api", name + " explicit prototype")]
        evidence.extend(
            Evidence(at, "context_setup", "Matching context/handle setup")
            for at in setup
            if at != ea
        )
        f = Finding(
            ea,
            function,
            context.algorithm,
            context.mode,
            "api_contract",
            source,
            evidence,
            fields + inherited,
            name,
            direction,
            notes,
            dict(context.attributes),
        )
        if spec.get("counter_default") is not None:
            f.materials.append(
                Material(
                    "counter",
                    status="api_default",
                    scalar=spec["counter_default"],
                    source=source,
                )
            )
        # Transfer newly created handle through an output slot or returned pointer.
        return f, context.clone()

    def auth_info(self, memory, p, source):
        header = read_bytes(memory, p, 8)
        if not header:
            return []
        size = int.from_bytes(header[:4], "little")
        version = int.from_bytes(header[4:], "little")
        expected = 88 if self.pointer_size == 8 else 64
        if size != expected or version != 1:
            return []
        layout = (
            {"nonce": (8, 16), "aad": (24, 32), "tag": (40, 48)}
            if self.pointer_size == 8
            else {"nonce": (8, 12), "aad": (16, 20), "tag": (24, 28)}
        )
        result = []
        for role, (po, lo) in layout.items():
            addr = memory.load(p.add(po), self.pointer_size)
            length = read_bytes(memory, p.add(lo), 4)
            if not isinstance(addr, (int, Pointer)) or length is None:
                continue
            n = int.from_bytes(length, "little")
            result.append(
                collect_field(
                    dict(role=role, arg=0, length=n),
                    [addr],
                    memory,
                    Context(),
                    source,
                    0,
                )
            )
        return result
