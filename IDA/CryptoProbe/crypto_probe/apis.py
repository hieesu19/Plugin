"""Explicit crypto API contracts; expanded schedules/opaque handles are not raw keys."""

import json, re
from pathlib import Path


def normalize_name(name):
    name = str(name or "").split("!")[-1]
    for _ in range(4):
        found = False
        for prefix in ("__imp_", "_imp__", "j_"):
            if name.startswith(prefix):
                name = name[len(prefix) :]
                found = True
                break
        if not found:
            break
    name = re.sub(r"@\d+$", "", name).lstrip("_")
    return name


def cipher_descriptor(name):
    name = normalize_name(name).lower()
    m = re.fullmatch(
        r"evp_aes_(128|192|256)_(ecb|cbc|ctr|cfb128|cfb8|cfb1|ofb|gcm)", name
    )
    if m:
        mode = m[2].upper()
        return dict(
            algorithm="AES",
            mode="CFB" if mode.startswith("CFB") else mode,
            key_length=int(m[1]) // 8,
            iv_length=0 if mode == "ECB" else 12 if mode == "GCM" else 16,
            cfb_segment_bits=int(mode[3:]) if mode.startswith("CFB") else None,
        )
    m = re.fullmatch(r"evp_des_(ecb|cbc|cfb64|cfb8|cfb1|ofb)", name)
    if m:
        return dict(
            algorithm="DES",
            mode="CFB" if m[1].startswith("cfb") else m[1].upper(),
            key_length=8,
            iv_length=0 if m[1] == "ecb" else 8,
            cfb_segment_bits=int(m[1][3:]) if m[1].startswith("cfb") else None,
        )
    if name in ("evp_chacha20", "evp_chacha20_poly1305"):
        return dict(
            algorithm="ChaCha20-Poly1305" if name.endswith("poly1305") else "ChaCha20",
            mode="AEAD" if name.endswith("poly1305") else "STREAM",
            key_length=32,
            iv_length=12 if name.endswith("poly1305") else 16,
            layout=(
                "IETF nonce 12 bytes"
                if name.endswith("poly1305")
                else "OpenSSL ChaCha20 IV = LE64 counter + 8-byte nonce"
            ),
        )
    if name in ("evp_rc4", "evp_rc4_40"):
        return dict(
            algorithm="RC4",
            mode="STREAM",
            key_length=5 if name.endswith("_40") else 16,
            iv_length=0,
        )
    return None


def parse_cipher_string(text):
    text = str(text).strip().lower().replace("-", "_")
    if text.startswith("aes_") and text.endswith("_cfb"):
        text += "128"
    if text.startswith("des_") and text.endswith("_cfb"):
        text += "64"
    if text.startswith("aes_"):
        return cipher_descriptor("EVP_" + text)
    if text in ("rc4", "chacha20", "chacha20_poly1305"):
        return cipher_descriptor("EVP_" + text)
    if text.startswith("des_"):
        return cipher_descriptor("EVP_" + text)
    return None


class ApiCatalog:
    def __init__(self, root=None):
        self.root = Path(root) if root else Path(__file__).parent / "rules"
        self.specs = {}
        self.errors = []
        for path in sorted(self.root.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                for s in data.get("apis", []):
                    self._validate(s)
                    for name in s["names"]:
                        self.specs[normalize_name(name)] = s
            except (ValueError, OSError, TypeError, KeyError) as exc:
                self.errors.append("%s: %s" % (path.name, exc))

    @staticmethod
    def _validate(s):
        if (
            not isinstance(s.get("names"), list)
            or not s["names"]
            or not all(isinstance(n, str) and n for n in s["names"])
        ):
            raise ValueError("API names must be nonempty strings")
        if not isinstance(s.get("argc"), int) or not 0 <= s["argc"] <= 24:
            raise ValueError("argc must be 0..24")
        events = {
            "direct",
            "evp_init",
            "context_use",
            "evp_ctrl",
            "set_padding",
            "set_key_length",
            "cipher_fetch",
            "setkey",
            "rsa_use",
            "rsa_setkey",
            "rsa_padding",
            "rsa_hash",
            "bignum_import",
            "bignum_word",
            "cng_open",
            "cng_property",
            "cng_key",
            "cng_import",
            "cng_use",
            "capi_import",
            "capi_property",
            "capi_use",
            "destroy_context",
            "kdf",
            "random",
        }
        if s.get("event") not in events:
            raise ValueError("unknown decoder event; use direct for a custom API")
        for k, v in s.items():
            if (
                k.endswith("_arg")
                and v is not None
                and (not isinstance(v, int) or not 0 <= v < s["argc"])
            ):
                raise ValueError("invalid argument index: " + k)
        for k, v in s.get("arg_sizes", {}).items():
            if not 0 <= int(k) < s["argc"] or v not in (1, 2, 4, 8, "c_long"):
                raise ValueError("invalid scalar ABI argument size")
        if s.get("success") not in (
            None,
            "void",
            "bool",
            "openssl",
            "mbedtls",
            "ntstatus",
            "zero",
            "pointer",
            "positive",
            "positive32",
        ):
            raise ValueError("unknown return contract")
        for p in s.get("writes", []):
            if not isinstance(p.get("arg"), int) or not 0 <= p["arg"] < s["argc"]:
                raise ValueError("invalid written buffer argument")
            if p.get("length_arg") is not None and not 0 <= p["length_arg"] < s["argc"]:
                raise ValueError("invalid output length argument")
        for p in s.get("fields", []):
            if not isinstance(p.get("role"), str) or not p["role"]:
                raise ValueError("field role must be a nonempty string")
            if p.get("kind", "bytes") not in (
                "bytes",
                "scalar",
                "pointer",
                "cstring",
                "utf16",
                "opaque",
            ):
                raise ValueError("invalid field kind")
            if not isinstance(p.get("arg"), int) or not 0 <= p["arg"] < s["argc"]:
                raise ValueError("argument index outside prototype")
            if p.get("length") is not None and (
                not isinstance(p["length"], int) or not 0 <= p["length"] <= 1048576
            ):
                raise ValueError("invalid fixed length")
            if p.get("length_arg") is not None and (
                not isinstance(p["length_arg"], int)
                or not 0 <= p["length_arg"] < s["argc"]
            ):
                raise ValueError("invalid length argument")
            if (
                not isinstance(p.get("length_divisor", 1), int)
                or p.get("length_divisor", 1) < 1
            ):
                raise ValueError("invalid length divisor")

    def lookup(self, name):
        return self.specs.get(normalize_name(name))

    def all(self):
        return list({id(s): s for s in self.specs.values()}.values())
