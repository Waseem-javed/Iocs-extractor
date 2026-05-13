# IPv4 — plain (1.2.3.4) and defanged (1.2.3[.]4 / 1[.]2[.]3[.]4)
IP_REGEX = r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b"

# Domains — plain and defanged ([.] notation); restricted to real TLDs to avoid
# matching filenames like loader.js or patch.exe
DOMAIN_REGEX = (
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))"
    r"+(?:com|net|org|io|ru|xyz|top|cloud|online|support|info|biz|site|"
    r"app|tech|co|uk|de|fr|nl|gov|edu|mil|mobi|int)\b"
)

# URLs — plain (https://) and defanged (hxxps://, hxxp://)
URL_REGEX = r"(?:hxxps?|https?)://[^\s\"<>,;\n]+"

# File Hashes — SHA256 (64 hex), SHA1 (40 hex), MD5 (32 hex); ordered longest first
HASH_SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
HASH_SHA1_REGEX   = r"\b[a-fA-F0-9]{40}\b"
HASH_MD5_REGEX    = r"\b[a-fA-F0-9]{32}\b"

# CVE IDs
CVE_REGEX = r"\bCVE-\d{4}-\d{4,7}\b"

# MITRE ATT&CK Technique / Sub-technique IDs (e.g. T1566, T1566.001)
TTP_REGEX = r"\bT\d{4}(?:\.\d{3})?\b"

# Email addresses — plain and defanged
EMAIL_REGEX = r"[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+(?:\[\.\]|\.))+[a-zA-Z]{2,}"

# Bitcoin wallet addresses — Bech32 (bc1q...) and Legacy (1.../3...)
BTC_REGEX = r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{6,87}|[13][a-zA-HJ-NP-Z0-9]{25,34})\b"

# Threat Actor aliases (named groups, numbered groups, known APTs)
THREAT_ACTOR_REGEX = (
    r"\b(?:TA-[A-Z][a-zA-Z0-9]+|FIN\d+|APT\d+|UNC-\d+|LAPSUS\$?"
    r"|Lazarus(?:\s+Group)?|Sandworm|Fancy\s+Bear|Cozy\s+Bear|Turla|Kimsuky"
    r"|LockBit|BlackCat|ALPHV|REvil|DarkSide|Conti|Hive|TA-505"
    r"|ShadowForge|UNC-2147)\b"
)

# Malware families and offensive tools
MALWARE_REGEX = (
    r"\b(?:RedLine|Emotet|Cobalt\s+Strike|Sliver|Mimikatz|Metasploit"
    r"|PowerShell\s+Empire|TrickBot|AgentTesla|AsyncRAT|NjRAT|QuasarRAT"
    r"|BlackCat|ALPHV|LockBit|Ryuk|Conti|REvil|Hive|NetSupportRAT"
    r"|IcedID|Qakbot|Dridex|Raccoon|Vidar|FormBook|GuLoader"
    r"|ShadowLoader|SfLoader)\b"
)

# Windows Registry Keys
REGISTRY_REGEX = r"\bHK(?:CU|LM|CR|U|CC)\\[^\s,\"';\n]+"

# Named Mutexes
MUTEX_REGEX = r"\bGlobal\\\\[^\s,\"';\n]+"

# User-Agent strings
UA_REGEX = r"Mozilla/[\d.]+\s*\([^)]+\)(?:\s+[^\s,\n\"]+)*"
