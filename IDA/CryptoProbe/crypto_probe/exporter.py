"""Export explicit facts and a decrypt draft; omitted fields are never filled with guessed defaults."""

import json
from .model import Finding

ALGORITHMS = {
    "AES": "aes",
    "DES": "des",
    "RC4": "rc4",
    "Salsa20": "salsa20",
    "ChaCha20": "chacha20",
    "ChaCha20-Poly1305": "chacha20-poly1305",
    "TEA": "tea",
    "XTEA": "xtea",
    "XXTEA": "xxtea",
    "RSA": "rsa",
}


def crypto_draft(f):
    config = {}
    missing = ["file header/trailer layout", "input/output paths"]
    facts = {}
    if f.algorithm in ALGORITHMS:
        config["algorithm"] = ALGORITHMS[f.algorithm]
    else:
        missing.append("exact algorithm / variant")
    if f.mode not in ("unknown", ""):
        config["mode"] = (
            "RSA"
            if f.algorithm == "RSA"
            else "STREAM" if f.mode == "STREAM" else f.mode
        )
    elif f.algorithm == "RSA":
        config["mode"] = "RSA"
    elif f.algorithm == "RC4":
        config["mode"] = "STREAM"
    else:
        missing.append("cipher mode")
    valid = {
        m.role: m
        for m in f.materials
        if m.status in ("recovered", "observed", "api_default")
    }
    for role, m in valid.items():
        facts[role] = {
            "hex": m.hex,
            "scalar": m.scalar,
            "length": m.length,
            "source": m.source,
        }
    if "key" in valid and valid["key"].hex:
        config.update(key=valid["key"].hex, key_encoding="hex", key_source="literal")
    elif f.algorithm != "RSA":
        missing.append("raw key")
    vector = next(
        (
            valid[r]
            for r in ("nonce", "counter_block", "iv")
            if r in valid and valid[r].hex
        ),
        None,
    )
    if vector:
        config.update(iv=vector.hex, iv_encoding="hex", iv_source="literal")
    elif f.mode not in ("ECB",) and f.algorithm not in ("RC4", "RSA"):
        missing.append("IV / nonce / counter block")
    if "counter" in valid and valid["counter"].scalar is not None:
        config["initial_counter"] = valid["counter"].scalar
    if f.algorithm == "ChaCha20" and vector:
        if vector.length == 8:
            config["variant"] = "original"
        elif vector.length == 12:
            config["variant"] = "ietf"
        else:
            missing.append("ChaCha nonce/counter layout")
    if f.algorithm == "RSA":
        for role, name in [("n", "rsa_n"), ("e", "rsa_e"), ("d", "rsa_d")]:
            if role in valid and valid[role].hex:
                config[name] = valid[role].hex
        if "pem" in valid and valid["pem"].hex:
            config["pem"] = bytes.fromhex(valid["pem"].hex).decode(
                "ascii", errors="replace"
            )
        if "d" not in valid:
            missing.append("RSA private key / d")
        for source, name in [
            ("rsa_padding", "rsa_padding"),
            ("oaep_hash", "oaep_hash"),
            ("mgf1_hash", "mgf_hash"),
        ]:
            if source in f.metadata:
                config[name] = f.metadata[source]
            else:
                missing.append(source)
        if "oaep_label" in valid:
            config["oaep_label"] = valid["oaep_label"].hex or ""
        else:
            missing.append("OAEP label presence / absence")
    if f.mode in ("CBC", "ECB"):
        if "padding" in f.metadata:
            config["padding"] = f.metadata["padding"]
        else:
            missing.append("padding / original size")
    if f.mode == "CFB":
        if f.metadata.get("cfb_segment_bits"):
            config["cfb_segment_bits"] = f.metadata["cfb_segment_bits"]
        else:
            missing.append("CFB segment size")
    if f.mode == "CTR":
        missing.extend(["counter offset/width", "counter endian"])
    if f.mode in ("GCM", "CCM", "AEAD"):
        if "aad" in valid:
            config.update(
                aad=valid["aad"].hex or "", aad_encoding="hex", aad_source="literal"
            )
        else:
            missing.append("AAD presence / absence")
        if "tag" in valid and valid["tag"].hex:
            config.update(
                tag=valid["tag"].hex,
                tag_encoding="hex",
                tag_source="literal",
                tag_bytes=valid["tag"].length,
            )
        else:
            missing.append("authentication tag and file location")
    if f.algorithm in ("TEA", "XTEA", "XXTEA"):
        missing.extend(["word endian", "delta / cycles", "block mode or XXTEA packing"])
    if f.confidence == "candidate":
        missing.append("confirm candidate algorithm / parameter-role binding")
    return {
        "schema": "crypto-probe/draft-1",
        "config": config,
        "facts": facts,
        "requires_review": sorted(set(missing)),
        "ready_to_run": False,
        "evidence": f.to_dict(hex_addresses=True),
        "note": "Explicit fields only. Verify omitted layout/padding/variant options before applying any defaults in a decryptor.",
    }


def markdown_report(result):
    lines = [
        "# Crypto Probe report",
        "",
        json.dumps(result.metadata, ensure_ascii=False),
        "",
    ]
    for f in result.findings:
        lines += [
            "## %#x · %s / %s" % (f.address, f.algorithm, f.mode),
            "",
            "Source: %s · confidence: %s · API: %s"
            % (f.source, f.confidence, f.api or "-"),
            "",
        ]
        for m in f.materials:
            lines.append(
                "- %s: %s · len=%s · hex=%s · value=%s"
                % (
                    m.role,
                    m.status,
                    m.length,
                    m.hex or "unknown",
                    m.scalar if m.scalar is not None else "",
                )
            )
        lines += (
            [""]
            + ["- Evidence %#x: %s" % (e.address, e.text) for e in f.evidence]
            + [""]
            + ["- " + n for n in f.notes]
            + [""]
        )
    lines += ["## Diagnostics", ""] + result.diagnostics
    return "\n".join(lines) + "\n"
