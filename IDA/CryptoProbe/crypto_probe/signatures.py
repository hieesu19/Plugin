"""Data fingerprints are algorithm/table evidence, never a key by themselves."""

from .model import Finding, Evidence


def multiply(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        high = a & 128
        a = (a << 1) & 255
        if high:
            a ^= 0x1B
        b >>= 1
    return r


def aes_sbox():
    out = []
    for x in range(256):
        inv = 0 if x == 0 else 1
        if x:
            for _ in range(254):
                inv = multiply(inv, x)
        r = inv
        for n in (1, 2, 3, 4):
            r ^= ((inv << n) | (inv >> (8 - n))) & 255
        out.append(r ^ 0x63)
    return bytes(out)


AES_SBOX = aes_sbox()
AES_INV = bytes(AES_SBOX.index(n) for n in range(256))
DES_S1 = bytes(
    [
        14,
        4,
        13,
        1,
        2,
        15,
        11,
        8,
        3,
        10,
        6,
        12,
        5,
        9,
        0,
        7,
        0,
        15,
        7,
        4,
        14,
        2,
        13,
        1,
        10,
        6,
        12,
        11,
        9,
        5,
        3,
        8,
        4,
        1,
        14,
        8,
        13,
        6,
        2,
        11,
        15,
        12,
        9,
        7,
        3,
        10,
        5,
        0,
        15,
        12,
        8,
        2,
        4,
        9,
        1,
        7,
        5,
        11,
        3,
        14,
        10,
        0,
        6,
        13,
    ]
)
DES_IP = bytes(
    [
        58,
        50,
        42,
        34,
        26,
        18,
        10,
        2,
        60,
        52,
        44,
        36,
        28,
        20,
        12,
        4,
        62,
        54,
        46,
        38,
        30,
        22,
        14,
        6,
        64,
        56,
        48,
        40,
        32,
        24,
        16,
        8,
        57,
        49,
        41,
        33,
        25,
        17,
        9,
        1,
        59,
        51,
        43,
        35,
        27,
        19,
        11,
        3,
        61,
        53,
        45,
        37,
        29,
        21,
        13,
        5,
        63,
        55,
        47,
        39,
        31,
        23,
        15,
        7,
    ]
)
DEFAULT_PATTERNS = [
    ("AES", "AES S-box", AES_SBOX),
    ("AES", "AES inverse S-box", AES_INV),
    ("DES", "DES S1 table", DES_S1),
    ("DES", "DES initial permutation", DES_IP),
    (
        "Salsa20 / ChaCha20",
        "sigma constant (shared; not enough to distinguish)",
        b"expand 32-byte k",
    ),
    (
        "Salsa20 / ChaCha20",
        "tau constant (shared; not enough to distinguish)",
        b"expand 16-byte k",
    ),
]


def data_scan(data, start=0, patterns=None):
    hits = []
    for algorithm, label, pattern in patterns or DEFAULT_PATTERNS:
        pos = 0
        count = 0
        while count < 128:
            index = data.find(pattern, pos)
            if index < 0:
                break
            ea = start + index
            hits.append(
                Finding(
                    ea,
                    ea,
                    algorithm,
                    "unknown",
                    "table_match",
                    "static",
                    [Evidence(ea, "constant_table", label)],
                    notes=[
                        "Constant/table occurrence identifies a possible implementation; it is not a raw key and does not establish the mode."
                    ],
                )
            )
            pos = index + max(1, len(pattern))
            count += 1
    return hits
