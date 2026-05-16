import hashlib
import re

# ── Helpers ───────────────────────────────────────────────────────────────────

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_BECH32_CHARSET = set("qpzry9x8gf2tvdw0s3jn54khce6mua7l")

_HEX_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")
_CVE_IN_TEXT_RE = re.compile(r"\bCVE-\d{4}-\d+", re.I)
_TTP_IN_TEXT_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

_SPURIOUS_SUBSTRINGS = (
    "technique title", "http://", "https://", "hxxp", "www.",
    "program files", "windows\\", "c:\\", "mitre att&ck",
    "joint cyber", "advisory", "infrastructure security",
    "federal bureau", "national cyber", "human rights council",
    "congressional research", "file path,", "malicious batch",
    "gather victim", "initial access", "sha256 malicious",
    "windows management", "microsoft 365", "jetbrains teamcity",
    "deep instinct", "cert polska", "cert-ua", "cisa insights",
    "the bank of", "the u.s. government", "the united nations",
    "zabbix", "zscaler", "winrar", "msedge", "allied networks",
)

_GENERIC_TOKENS = frozenset({
    "api", "av", "alert", "calc", "command", "dll", "edr", "eu", "ic",
    "kb", "lnk", "nas", "ntlm", "pdf", "sam", "sha1", "sha256", "md5",
    "sql", "shell", "javascript", "needs", "file path", "deploy",
    "discovery", "cyber", "bmp", "programdata%", "teamcity", "id:1",
    "infinityfreeapp", "defender advanced threat", "credential access",
    "initial access", "gather victim", "modify tools", "server software",
    "social engineering campaign", "post-compromise threat activity",
    "critical infrastructure", "control technique", "windows task schedule",
    "windows management", "windows command", "logon autostart",
})


def normalize(s: str) -> str:
    """Restore defanged IOCs to canonical form."""
    return s.replace("[.]", ".").replace("hxxps", "https").replace("hxxp", "http")


def collapse_ws(s: str) -> str:
    return " ".join(s.split())


def find_all(pattern: str, src: str, flags: int = 0) -> list[str]:
    """Return sorted unique matches, normalized."""
    results: set[str] = set()
    for m in re.findall(pattern, src, flags):
        s = collapse_ws(normalize(m.strip()))
        if s:
            results.add(s)
    return sorted(results)


def classify_hash(h: str) -> str:
    length = len(h)
    return {64: "SHA256", 40: "SHA1", 32: "MD5"}.get(length, "UNKNOWN")


def is_hex_digest(s: str) -> bool:
    """True for MD5/SHA1/SHA256-style hex strings."""
    return len(s) in (32, 40, 64) and bool(_HEX_HASH_RE.match(s))


def _b58decode(s: str) -> bytes:
    num = 0
    for c in s:
        try:
            num = num * 58 + _BASE58_ALPHABET.index(c)
        except ValueError as exc:
            raise ValueError(f"invalid base58: {c}") from exc
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + combined


def _base58check_valid(addr: str) -> bool:
    if not addr or any(c not in _BASE58_ALPHABET for c in addr):
        return False
    try:
        raw = _b58decode(addr)
    except ValueError:
        return False
    if len(raw) < 5:
        return False
    payload, checksum = raw[:-4], raw[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return checksum == expected


def _bech32_polymod(values: list[int]) -> int:
    generators = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def _bech32_hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32_verify_checksum(hrp: str, data: list[int]) -> bool:
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == 1


def _bech32_decode(addr: str) -> bool:
    if not addr.startswith("bc1"):
        return False
    addr = addr.lower()
    if any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if addr != addr.lower() and addr != addr.upper():
        return False
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data_part = addr[:pos], addr[pos + 1:]
    data: list[int] = []
    for c in data_part:
        if c not in _BECH32_CHARSET:
            return False
        data.append("qpzry9x8gf2tvdw0s3jn54khce6mua7l".index(c))
    return _bech32_verify_checksum(hrp, data)


def is_valid_bitcoin_address(addr: str) -> bool:
    """Reject file hashes and strings that fail Base58Check / Bech32 validation."""
    addr = addr.strip()
    if not addr or is_hex_digest(addr):
        return False
    if addr.startswith("bc1"):
        return 14 <= len(addr) <= 74 and _bech32_decode(addr)
    if addr[0] in "13" and 26 <= len(addr) <= 35:
        return _base58check_valid(addr)
    return False


def filter_bitcoin_wallets(candidates: list[str], known_hashes: set[str]) -> list[str]:
    known = {h.lower() for h in known_hashes}
    out: list[str] = []
    for addr in candidates:
        if addr.lower() in known:
            continue
        if is_valid_bitcoin_address(addr):
            out.append(addr)
    return sorted(set(out))


def is_spurious_entity(text: str) -> bool:
    """Filter NER false positives from unknown actor/malware lists."""
    cleaned = collapse_ws(text)
    if len(cleaned) < 4:
        return True
    lower = cleaned.lower()
    if _HEX_HASH_RE.match(cleaned):
        return True
    if _CVE_IN_TEXT_RE.search(cleaned) or _TTP_IN_TEXT_RE.search(cleaned):
        return True
    if lower in _GENERIC_TOKENS:
        return True
    if any(s in lower for s in _SPURIOUS_SUBSTRINGS):
        return True
    if re.fullmatch(r"[A-Z]{2,5}", cleaned):
        return True
    if cleaned[0] in "•▪-" or cleaned.endswith(".exe"):
        return True
    if "|" in cleaned or ".*" in cleaned:
        return True
    if re.search(r"\.(gov|org|com)/", lower):
        return True
    return False


def is_valid_registry_key(key: str) -> bool:
    """Drop YARA-style patterns mistaken for registry paths."""
    if "|" in key or ".*" in key:
        return False
    return key.startswith("HK") and "\\" in key


def overlaps_known_actor(name: str, known_actors: list[str]) -> bool:
    """Skip unknown NER hits that duplicate a known actor alias."""
    n = re.sub(r"^the\s+", "", collapse_ws(name).lower())
    for known in known_actors:
        k = re.sub(r"^the\s+", "", collapse_ws(known).lower())
        if n == k or n in k or k in n:
            return True
    return False
