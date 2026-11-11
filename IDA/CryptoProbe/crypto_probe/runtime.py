"""Framework-independent capture engine; IDA hook supplies registers and fresh memory."""

import copy
from .abi import ABI, success
from .memory import PartialMemory, Tagged, Unknown
from .materials import ApiDecoder, Contexts, Context, context_key, read_bytes
from .apis import cipher_descriptor, normalize_name
from .model import Evidence, Material


class RuntimeEngine:
    def __init__(self, abi, register, read, endian="little"):
        self.abi = ABI(abi, register, read, endian)
        self.read = read
        self.endian = endian
        self.contexts = Contexts()
        self.pending = {}
        self.findings = []
        self.generation = 0

    def reset(self):
        self.contexts = Contexts()
        self.pending.clear()
        self.generation += 1

    def capture(self, binding, ea, tid, return_ea=None, site="call"):
        spec = binding["spec"]
        name = normalize_name(binding["name"])
        values = self.abi.arguments(spec["argc"], site, spec.get("arg_sizes"))
        mem = PartialMemory(self.read, self.endian)
        proposed = self.contexts.clone()
        # A descriptor known at this callsite is data-flow evidence, not an opaque pointer dereference.
        hint = binding.get("hint", {})
        sv = binding.get("static_values", [])
        index = spec.get("cipher_arg")
        if index is not None and index < len(values) and values[index] != 0:
            descriptor = self.contexts.values.get(context_key(values[index]))
            if descriptor and descriptor.attributes.get("descriptor_kind") == "cipher":
                values[index] = Tagged("cipher", descriptor.attributes)
            elif (
                index < len(sv)
                and isinstance(sv[index], Tagged)
                and sv[index].kind == "cipher"
            ):
                values[index] = sv[index]
        key = (
            context_key(values[spec["context_arg"]])
            if spec.get("context_arg") is not None
            else None
        )
        ctx = proposed.get(key) if key is not None else Context()
        # Hints supply sizes only; never inject static key bytes into a runtime result.
        for k in ("key_length", "iv_length", "layout", "cfb_segment_bits"):
            if k in hint:
                ctx.attributes.setdefault(k, hint[k])
        f, created = ApiDecoder(proposed, self.abi.word).decode(
            name, spec, values, mem, ea, binding.get("function", ea), "debug"
        )
        f.metadata.update(
            thread=tid,
            generation=self.generation,
            capture_site=site,
            api_return="pending",
            abi=self.abi.name,
        )
        if binding.get("candidate"):
            f.confidence = "candidate"
            f.notes.append(
                "Custom primitive argument role is a structural candidate; confirm the mapping."
            )
        f.evidence.append(
            Evidence(
                ea,
                "runtime",
                "Fresh debugger memory read before call/at entry; no IDB fallback.",
            )
        )
        self.findings.append(f)
        if return_ea is not None:
            self.pending.setdefault((tid, return_ea), []).append(
                dict(
                    binding=binding,
                    values=values,
                    created=created,
                    proposed=proposed,
                    finding=f,
                    key=key,
                )
            )
        return f

    def finish(self, ea, tid):
        stack = self.pending.get((tid, ea), [])
        if not stack:
            return None
        pending = stack.pop()
        if not stack:
            self.pending.pop((tid, ea), None)
        binding = pending["binding"]
        spec = binding["spec"]
        values = pending["values"]
        f = pending["finding"]
        rv = self.abi.return_value()
        name = normalize_name(binding["name"])
        event = spec["event"]
        contract = spec.get(
            "success",
            (
                "openssl"
                if name.startswith("EVP_") and event != "cipher_fetch"
                else (
                    "mbedtls"
                    if name.startswith("mbedtls_")
                    and event not in ("setkey", "destroy_context")
                    else None
                )
            ),
        )
        checked = rv
        if contract == "positive" and isinstance(rv, int):
            width = self.abi.word * 8
            checked = rv & ((1 << width) - 1)
            checked = (
                checked - (1 << width) if checked & (1 << (width - 1)) else checked
            )
        ok = success(checked, contract)
        f.metadata.update(
            api_return=(
                rv
                if isinstance(rv, int) and contract != "void"
                else "void" if contract == "void" else "unknown"
            ),
            api_success=ok,
        )
        mem = PartialMemory(self.read, self.endian)
        if not ok:
            f.notes.append(
                "API reported failure; captured input bytes remain observations, no context/handle effect committed."
            )
            return f
        key = pending["key"]
        created = pending["created"]
        proposed = pending["proposed"]
        if key is not None:
            if event == "destroy_context":
                self.contexts.values.pop(key, None)
            elif key in proposed.values:
                self.contexts.values[key] = proposed.values[key]
        if spec.get("output_arg") is not None:
            out = values[spec["output_arg"]]
            raw = read_bytes(mem, out, self.abi.word)
            if raw:
                handle = int.from_bytes(raw, self.endian)
                if handle:
                    self.contexts.values[context_key(handle)] = created
                f.metadata["created_handle"] = handle
        if event == "cipher_fetch" and isinstance(rv, int) and rv:
            role = next((m for m in f.materials if m.role == "cipher_name"), None)
            from .apis import parse_cipher_string

            parsed = parse_cipher_string(role.expression) if role else None
            if parsed:
                parsed["descriptor_kind"] = "cipher"
                c = Context(parsed["algorithm"], parsed["mode"], parsed)
                self.contexts.values[context_key(rv)] = c
        if event in ("bignum_import", "bignum_word") and isinstance(rv, int):
            target = rv if event == "bignum_import" else values[spec["context_arg"]]
            if target:
                self.contexts.values[context_key(target)] = created
        if event in ("random", "kdf"):
            oi = spec.get("random_output_arg", spec.get("derived_output_arg"))
            li = spec.get("random_length_arg", spec.get("derived_length_arg"))
            n = values[li]
            if name == "getrandom" and isinstance(n, int) and isinstance(rv, int):
                n = min(n, rv)
            raw = read_bytes(mem, values[oi], n)
            if raw is not None:
                f.materials.append(
                    Material(
                        "random_bytes" if event == "random" else "derived_key",
                        "observed",
                        hex=raw.hex(),
                        length=len(raw),
                        source="debug",
                        notes=[
                            "Read after successful producer return; role in subsequent encryption still requires a consumer."
                        ],
                    )
                )
        for profile in spec.get("fields", []):
            if profile["role"] in spec.get("output_fields", []):
                from .materials import collect_field

                m = collect_field(profile, values, mem, created, "debug", ea)
                m.notes.append("Read after successful return.")
                f.materials = [x for x in f.materials if x.role != m.role] + [m]
        if event == "cng_use" and f.direction == "encrypt" and len(values) > 3:
            from .materials import pointer

            p = pointer(values[3])
            if p:
                for m in ApiDecoder(pointer_size=self.abi.word).auth_info(
                    mem, p, "debug"
                ):
                    if m.role == "tag":
                        m.notes.append("Read after successful BCryptEncrypt return.")
                        f.materials = [x for x in f.materials if x.role != "tag"] + [m]
        if event == "evp_ctrl" and values[1] == 0x10 and isinstance(values[2], int):
            from .materials import collect_field

            m = collect_field(
                dict(role="tag", arg=3, length=values[2]),
                values,
                mem,
                created,
                "debug",
                ea,
            )
            m.notes.append("EVP GET_TAG output read after successful return.")
            f.materials = [x for x in f.materials if x.role != "tag"] + [m]
        if (
            name.startswith("crypto_aead_")
            and f.direction == "encrypt"
            and spec.get("tag_length")
        ):
            from .materials import pointer, collect_field, MAX_CAPTURE

            raw = read_bytes(mem, values[1], 8)
            length = int.from_bytes(raw, self.endian) if raw else None
            n = spec["tag_length"]
            p = pointer(values[0])
            if p and isinstance(length, int) and n <= length <= MAX_CAPTURE:
                m = collect_field(
                    dict(role="tag", arg=0, length=n),
                    [p.add(length - n)],
                    mem,
                    created,
                    "debug",
                    ea,
                )
                m.notes.append(
                    "Combined AEAD tag read after successful return; clen_p is uint64."
                )
                f.materials = [x for x in f.materials if x.role != "tag"] + [m]
        return f
