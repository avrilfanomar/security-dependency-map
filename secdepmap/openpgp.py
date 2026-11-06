"""Minimal, read-only OpenPGP (RFC 4880 / RFC 9580) packet parser.

Only what a supply-chain inventory needs: public keys & subkeys
(fingerprint, algorithm, size/curve, creation, expiry, revocation), user IDs,
and the issuer / hash algorithm of detached or clearsigned signatures.
No cryptographic verification is performed - APT/gpgv do that; we only
*describe* the trust material. Pure Python so we never need to execute gpg.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import struct

PUBKEY_ALGOS = {
    1: "RSA", 2: "RSA-E", 3: "RSA-S", 16: "ElGamal", 17: "DSA", 18: "ECDH",
    19: "ECDSA", 20: "ElGamal-legacy", 22: "EdDSA", 25: "X25519", 26: "X448",
    27: "Ed25519", 28: "Ed448",
}
HASH_ALGOS = {1: "MD5", 2: "SHA1", 3: "RIPEMD160", 8: "SHA256", 9: "SHA384",
              10: "SHA512", 11: "SHA224", 12: "SHA3-256", 14: "SHA3-512"}
WEAK_HASHES = {"MD5", "SHA1", "RIPEMD160"}
CURVES = {
    "2b06010401da470f01": "Ed25519", "2b060104019755010501": "Curve25519",
    "2a8648ce3d030107": "NIST P-256", "2b81040022": "NIST P-384", "2b81040023": "NIST P-521",
    "2b2403030208010107": "brainpoolP256r1", "2b240303020801010b": "brainpoolP384r1",
    "2b240303020801010d": "brainpoolP512r1", "2b8104000a": "secp256k1",
}


def dearmor(data: bytes):
    """Return a list of binary blobs from ASCII-armored input (or [data] if binary)."""
    if b"-----BEGIN PGP" not in data:
        return [data]
    blobs = []
    lines = data.decode("ascii", errors="replace").splitlines()
    i = 0
    while i < len(lines):
        if lines[i].startswith("-----BEGIN PGP") and "SIGNED MESSAGE" not in lines[i]:
            i += 1
            while i < len(lines) and lines[i].strip() and ":" in lines[i]:
                i += 1  # armor headers
            b64 = []
            while i < len(lines) and not lines[i].startswith("-----END PGP"):
                ln = lines[i].strip()
                if ln.startswith("=") and len(ln) == 5:
                    pass  # CRC24
                elif ln:
                    b64.append(ln)
                i += 1
            try:
                blobs.append(base64.b64decode("".join(b64)))
            except (binascii.Error, ValueError):
                pass
        i += 1
    return blobs


def packets(data: bytes):
    """Yield (tag, body) for each packet."""
    i, n = 0, len(data)
    while i < n:
        b = data[i]
        if not b & 0x80:
            return
        if b & 0x40:  # new format
            tag = b & 0x3F
            i += 1
            if i >= n:
                return
            l1 = data[i]
            if l1 < 192:
                ln, i = l1, i + 1
            elif l1 < 224:
                if i + 1 >= n:
                    return
                ln, i = ((l1 - 192) << 8) + data[i + 1] + 192, i + 2
            elif l1 == 255:
                ln, i = struct.unpack(">I", data[i + 1:i + 5])[0], i + 5
            else:  # partial body: concatenate chunks
                body = b""
                while True:
                    ln = 1 << (l1 & 0x1F)
                    body += data[i + 1:i + 1 + ln]
                    i += 1 + ln
                    if i >= n:
                        break
                    l1 = data[i]
                    if l1 < 224 or l1 == 255:
                        if l1 < 192:
                            ln, i = l1, i + 1
                        elif l1 < 224:
                            ln, i = ((l1 - 192) << 8) + data[i + 1] + 192, i + 2
                        else:
                            ln, i = struct.unpack(">I", data[i + 1:i + 5])[0], i + 5
                        body += data[i:i + ln]
                        i += ln
                        break
                yield tag, body
                continue
        else:  # old format
            tag = (b >> 2) & 0x0F
            lt = b & 3
            i += 1
            if lt == 0:
                ln, i = data[i], i + 1
            elif lt == 1:
                ln, i = struct.unpack(">H", data[i:i + 2])[0], i + 2
            elif lt == 2:
                ln, i = struct.unpack(">I", data[i:i + 4])[0], i + 4
            else:
                ln = n - i
        yield tag, data[i:i + ln]
        i += ln


def _subpackets(buf):
    i = 0
    while i < len(buf):
        l1 = buf[i]
        if l1 < 192:
            ln, i = l1, i + 1
        elif l1 < 255:
            ln, i = ((l1 - 192) << 8) + buf[i + 1] + 192, i + 2
        else:
            ln, i = struct.unpack(">I", buf[i + 1:i + 5])[0], i + 5
        if ln == 0 or i + ln > len(buf):
            return
        yield buf[i] & 0x7F, buf[i + 1:i + ln]
        i += ln


def parse_signature(body):
    """Return dict(version, sigtype, pubalgo, hash, created, issuer_keyid, issuer_fpr, key_expires_rel)."""
    if not body:
        return None
    v = body[0]
    out = {"version": v}
    if v == 3:
        out.update(sigtype=body[2], created=struct.unpack(">I", body[3:7])[0],
                   issuer_keyid=body[7:15].hex().upper(),
                   pubalgo=PUBKEY_ALGOS.get(body[15], str(body[15])),
                   hash=HASH_ALGOS.get(body[16], str(body[16])))
        return out
    if v not in (4, 5, 6):
        return out
    out["sigtype"] = body[1]
    out["pubalgo"] = PUBKEY_ALGOS.get(body[2], str(body[2]))
    out["hash"] = HASH_ALGOS.get(body[3], str(body[3]))
    if v == 6:
        hl = struct.unpack(">I", body[4:8])[0]
        hashed = body[8:8 + hl]
        p = 8 + hl
        ul = struct.unpack(">I", body[p:p + 4])[0]
        unhashed = body[p + 4:p + 4 + ul]
    else:
        hl = struct.unpack(">H", body[4:6])[0]
        hashed = body[6:6 + hl]
        p = 6 + hl
        ul = struct.unpack(">H", body[p:p + 2])[0]
        unhashed = body[p + 2:p + 2 + ul]
    for area in (hashed, unhashed):
        for t, d in _subpackets(area):
            if t == 2 and len(d) >= 4:
                out["created"] = struct.unpack(">I", d[:4])[0]
            elif t == 9 and len(d) >= 4 and area is hashed:
                out["key_expires_rel"] = struct.unpack(">I", d[:4])[0]
            elif t == 3 and len(d) >= 4 and area is hashed:
                out["sig_expires_rel"] = struct.unpack(">I", d[:4])[0]
            elif t == 16 and len(d) >= 8:
                out.setdefault("issuer_keyid", d[:8].hex().upper())
            elif t == 33 and len(d) >= 21:
                out["issuer_fpr"] = d[1:].hex().upper()
    if "issuer_fpr" in out and "issuer_keyid" not in out:
        out["issuer_keyid"] = out["issuer_fpr"][-16:] if v == 4 else out["issuer_fpr"][:16]
    return out


def parse_pubkey(body):
    v = body[0]
    created = struct.unpack(">I", body[1:5])[0]
    if v == 3:
        algo = body[7]
        rest = body[8:]
    elif v in (4, 5, 6):
        algo = body[5]
        rest = body[6:] if v == 4 else body[10:]
    else:
        return {"version": v, "created": created, "algo": "unknown", "bits": None}
    name = PUBKEY_ALGOS.get(algo, str(algo))
    bits, curve = None, None
    if algo in (1, 2, 3, 16, 17, 20) and len(rest) >= 2:
        bits = struct.unpack(">H", rest[:2])[0]
    elif algo in (18, 19, 22) and rest:
        oid = rest[1:1 + rest[0]].hex()
        curve = CURVES.get(oid, "oid:" + oid)
        bits = {"Ed25519": 256, "Curve25519": 256, "NIST P-256": 256, "NIST P-384": 384,
                "NIST P-521": 521, "secp256k1": 256}.get(curve)
    elif algo in (25, 27):
        bits, curve = 256, ("X25519" if algo == 25 else "Ed25519")
    elif algo in (26, 28):
        bits, curve = 448, ("X448" if algo == 26 else "Ed448")
    if v == 4:
        fpr = hashlib.sha1(b"\x99" + struct.pack(">H", len(body)) + body).hexdigest().upper()
        keyid = fpr[-16:]
    elif v in (5, 6):
        prefix = b"\x9a" if v == 5 else b"\x9b"
        fpr = hashlib.sha256(prefix + struct.pack(">I", len(body)) + body).hexdigest().upper()
        keyid = fpr[:16]
    else:
        fpr, keyid = None, None
    return {"version": v, "created": created, "algo": name, "bits": bits, "curve": curve,
            "fingerprint": fpr, "keyid": keyid}


def parse_keyring(data: bytes):
    """Parse transferable public keys. Returns a list of key dicts."""
    keys = []
    for blob in dearmor(data):
        cur, last_sub = None, None
        for tag, body in packets(blob):
            try:
                if tag == 6:
                    cur = parse_pubkey(body)
                    cur.update(uids=[], subkeys=[], revoked=False, expires=None)
                    keys.append(cur)
                    last_sub = None
                elif tag == 14 and cur is not None:
                    last_sub = parse_pubkey(body)
                    last_sub.update(expires=None, revoked=False)
                    cur["subkeys"].append(last_sub)
                elif tag == 13 and cur is not None:
                    cur["uids"].append(body.decode("utf-8", errors="replace"))
                elif tag == 2 and cur is not None:
                    sig = parse_signature(body)
                    if not sig or "sigtype" not in sig:
                        continue
                    st = sig["sigtype"]
                    own = sig.get("issuer_keyid") in (cur.get("keyid"), None) or \
                        sig.get("issuer_fpr") == cur.get("fingerprint")
                    if not own:
                        continue
                    if st in (0x10, 0x11, 0x12, 0x13, 0x1F) and last_sub is None:
                        if sig.get("created", 0) >= cur.get("_selfsig_t", 0):
                            cur["_selfsig_t"] = sig.get("created", 0)
                            rel = sig.get("key_expires_rel")
                            cur["expires"] = cur["created"] + rel if rel else None
                            cur["selfsig_hash"] = sig.get("hash")
                    elif st == 0x18 and last_sub is not None:
                        rel = sig.get("key_expires_rel")
                        last_sub["expires"] = last_sub["created"] + rel if rel else None
                    elif st == 0x20:
                        cur["revoked"] = True
                    elif st == 0x28 and last_sub is not None:
                        last_sub["revoked"] = True
            except (struct.error, IndexError):
                continue
    for k in keys:
        k.pop("_selfsig_t", None)
    return keys


def clearsign_signatures(text: str):
    """Signatures found in a clearsigned document (e.g. APT InRelease)."""
    if "-----BEGIN PGP SIGNATURE-----" not in text:
        return []
    part = text[text.index("-----BEGIN PGP SIGNATURE-----"):]
    sigs = []
    for blob in dearmor(part.encode("ascii", errors="replace")):
        for tag, body in packets(blob):
            if tag == 2:
                try:
                    s = parse_signature(body)
                except (struct.error, IndexError):
                    s = None
                if s:
                    sigs.append(s)
    return sigs


def clearsign_body(text: str):
    """Strip the clearsign envelope and return the signed text."""
    if not text.startswith("-----BEGIN PGP SIGNED MESSAGE-----"):
        return text
    _, _, rest = text.partition("\n\n")
    body, _, _ = rest.partition("-----BEGIN PGP SIGNATURE-----")
    return "\n".join(ln[2:] if ln.startswith("- ") else ln for ln in body.splitlines())
