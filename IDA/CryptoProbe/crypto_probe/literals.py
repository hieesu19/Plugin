"""Strict decoder for Hex-Rays escaped cot_str text; no eval or zero padding."""


def c_literal_bytes(text):
    out = bytearray()
    i = 0
    escapes = {
        "a": 7,
        "b": 8,
        "f": 12,
        "n": 10,
        "r": 13,
        "t": 9,
        "v": 11,
        "\\": 92,
        '"': 34,
        "'": 39,
        "?": 63,
    }
    while i < len(text):
        c = text[i]
        i += 1
        if c != "\\":
            if ord(c) > 255:
                return None
            out.append(ord(c))
            continue
        if i >= len(text):
            return None
        c = text[i]
        i += 1
        if c in escapes:
            out.append(escapes[c])
        elif c in "01234567":
            digits = c
            while len(digits) < 3 and i < len(text) and text[i] in "01234567":
                digits += text[i]
                i += 1
            n = int(digits, 8)
            if n > 255:
                return None
            out.append(n)
        elif c == "x":
            digits = ""
            while i < len(text) and text[i] in "0123456789abcdefABCDEF":
                digits += text[i]
                i += 1
            if not digits or int(digits, 16) > 255:
                return None
            out.append(int(digits, 16))
        else:
            return None
    return bytes(out)
