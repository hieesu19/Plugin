"""Bounded DER/PEM and documented Windows key-blob readers (stdlib only)."""

import base64, math, re, struct

RSA_OID = bytes.fromhex("2a864886f70d010101")


def tlv(data, offset=0):
    if offset + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[offset]
    length = data[offset + 1]
    start = offset + 2
    if length & 128:
        n = length & 127
        if not 1 <= n <= 4 or start + n > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[start : start + n], "big")
        start += n
    if length > 1048576 or start + length > len(data):
        raise ValueError("truncated/oversized DER value")
    return tag, data[start : start + length], start + length


def children(data):
    out = []
    offset = 0
    while offset < len(data):
        tag, value, offset = tlv(data, offset)
        out.append((tag, value))
        if len(out) > 64:
            raise ValueError("too many DER fields")
    return out


def integer(raw):
    if not raw or raw[0] & 128:
        raise ValueError("negative/empty ASN.1 integer")
    return int.from_bytes(raw, "big")


def rsa_numbers(der, private=None):
    tag, body, end = tlv(der)
    if tag != 0x30 or end != len(der):
        raise ValueError("expected complete DER SEQUENCE")
    fields = children(body)
    # SubjectPublicKeyInfo: AlgorithmIdentifier + BIT STRING.
    if len(fields) == 2 and fields[0][0] == 0x30 and fields[1][0] == 3:
        alg = children(fields[0][1])
        if not alg or alg[0] != (6, RSA_OID):
            raise ValueError("not RSA algorithm OID")
        bit = fields[1][1]
        if not bit or bit[0] != 0:
            raise ValueError("invalid RSA BIT STRING")
        return rsa_numbers(bit[1:], False)
    # PKCS8 PrivateKeyInfo; encrypted PKCS8 deliberately not decoded.
    if (
        len(fields) >= 3
        and fields[0][0] == 2
        and fields[1][0] == 0x30
        and fields[2][0] == 4
    ):
        alg = children(fields[1][1])
        if not alg or alg[0] != (6, RSA_OID):
            raise ValueError("not RSA private key OID")
        return rsa_numbers(fields[2][1], True)
    if len(fields) == 2 and all(t == 2 for t, _ in fields):
        result = dict(n=integer(fields[0][1]), e=integer(fields[1][1]))
    elif len(fields) >= 9 and all(t == 2 for t, _ in fields[:9]):
        if integer(fields[0][1]) != 0:
            raise ValueError("multi-prime RSA requires separate handling")
        result = dict(
            zip(
                ("n", "e", "d", "p", "q", "dp", "dq", "qi"),
                [integer(v) for _, v in fields[1:9]],
            )
        )
        if result["p"] * result["q"] != result["n"]:
            raise ValueError("RSA p*q does not match n")
    else:
        raise ValueError("unsupported RSA DER layout")
    if result["n"] <= 0 or result["e"] < 3 or result["e"] % 2 == 0:
        raise ValueError("invalid RSA public values")
    return result


PEM_RE = re.compile(
    rb"-----BEGIN (RSA PRIVATE KEY|PRIVATE KEY|RSA PUBLIC KEY|PUBLIC KEY|ENCRYPTED PRIVATE KEY)-----[\s\S]{1,262144}?-----END \1-----"
)


def parse_pem(raw):
    m = PEM_RE.search(raw)
    if not m:
        raise ValueError("complete PEM block not found")
    block = m[0]
    label = m[1].decode()
    result = {
        "pem": block.decode("ascii"),
        "label": label,
        "numbers": {},
        "algorithm": "unknown",
    }
    if label == "ENCRYPTED PRIVATE KEY" or b"Proc-Type: 4,ENCRYPTED" in block:
        result["encrypted"] = True
        return result
    data = b"".join(block.splitlines()[1:-1])
    der = base64.b64decode(data, validate=True)
    result["numbers"] = rsa_numbers(der)
    result["algorithm"] = "RSA"
    return result


def parse_blob(raw):
    """Returns only data whose header/layout can be checked; opaque blobs stay opaque."""
    if len(raw) < 12:
        return None
    magic = int.from_bytes(raw[:4], "little")
    if magic == 0x4D42444B:  # BCRYPT_KEY_DATA_BLOB_MAGIC
        version, length = struct.unpack_from("<II", raw, 4)
        if version != 1 or length < 1 or length > 4096 or len(raw) < 12 + length:
            return None
        return {
            "format": "BCRYPT_KEY_DATA_BLOB",
            "key": raw[12 : 12 + length],
            "algorithm": "unknown",
        }
    if magic in (0x31415352, 0x32415352, 0x33415352) and len(raw) >= 24:
        _, bits, el, nl, pl, ql = struct.unpack_from("<6I", raw)
        if bits < 128 or bits > 16384 or nl != (bits + 7) // 8 or el < 1 or el > 32:
            return None
        sizes = (
            [el, nl]
            + ([pl, ql] if magic != 0x31415352 else [])
            + ([pl, ql, pl, nl] if magic == 0x33415352 else [])
        )
        if any(n < 1 or n > 4096 for n in sizes) or 24 + sum(sizes) > len(raw):
            return None
        names = (
            ["e", "n"]
            + (["p", "q"] if magic != 0x31415352 else [])
            + (["dp", "dq", "qi", "d"] if magic == 0x33415352 else [])
        )
        pos = 24
        numbers = {}
        for name, size in zip(names, sizes):
            numbers[name] = int.from_bytes(raw[pos : pos + size], "big")
            pos += size
        if "p" in numbers:
            if numbers["p"] * numbers["q"] != numbers["n"]:
                return None
            if "d" not in numbers:
                try:
                    numbers["d"] = pow(
                        numbers["e"], -1, math.lcm(numbers["p"] - 1, numbers["q"] - 1)
                    )
                except ValueError:
                    return None
        return {
            "format": "BCRYPT_RSA_BLOB",
            "algorithm": "RSA",
            "numbers": numbers,
            "d_derived": magic == 0x32415352,
        }
    # CryptoAPI PUBLICKEYSTRUC (8 bytes), followed by data specific to bType.
    btype, version, reserved, alg = struct.unpack_from("<BBHI", raw)
    algorithms = {
        0x660E: "AES",
        0x660F: "AES",
        0x6610: "AES",
        0x6601: "DES",
        0x6801: "RC4",
        0xA400: "RSA",
        0x2400: "RSA",
    }
    if version != 2 or reserved != 0 or alg not in algorithms:
        return None
    if btype == 8:
        length = struct.unpack_from("<I", raw, 8)[0]
        if not 1 <= length <= 4096 or len(raw) < 12 + length:
            return None
        return {
            "format": "PLAINTEXTKEYBLOB",
            "key": raw[12 : 12 + length],
            "algorithm": algorithms[alg],
        }
    if btype not in (6, 7) or len(raw) < 20 or algorithms[alg] != "RSA":
        return None
    rsamagic, bits, e = struct.unpack_from("<III", raw, 8)
    nlen = (bits + 7) // 8
    if (
        bits < 128
        or bits > 16384
        or bits % 16
        or rsamagic != (0x31415352 if btype == 6 else 0x32415352)
    ):
        return None
    sizes = [nlen] + ([nlen // 2] * 5 + [nlen] if btype == 7 else [])
    if 20 + sum(sizes) > len(raw):
        return None
    names = ["n"] + (["p", "q", "dp", "dq", "qi", "d"] if btype == 7 else [])
    pos = 20
    numbers = {"e": e}
    for name, size in zip(names, sizes):
        numbers[name] = int.from_bytes(raw[pos : pos + size], "little")
        pos += size
    if "p" in numbers and numbers["p"] * numbers["q"] != numbers["n"]:
        return None
    return {"format": "CryptoAPI_RSA_BLOB", "algorithm": "RSA", "numbers": numbers}
