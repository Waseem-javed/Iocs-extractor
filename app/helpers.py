import re

# ── Helpers ───────────────────────────────────────────────────────────────────

def normalize(s: str) -> str:
    """Restore defanged IOCs to canonical form."""
    return s.replace("[.]", ".").replace("hxxps", "https").replace("hxxp", "http")


def find_all(pattern: str, src: str, flags: int = 0) -> list[str]:
    """Return sorted unique matches, normalized."""
    return sorted(set(normalize(m.strip()) for m in re.findall(pattern, src, flags)))


def classify_hash(h: str) -> str:
    length = len(h)
    return {64: "SHA256", 40: "SHA1", 32: "MD5"}.get(length, "UNKNOWN")