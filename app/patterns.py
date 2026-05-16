
# ── Benign Filtering ─────────────────────────────────────────────────────────
BENIGN_ORGS = {
    "Microsoft", "Google", "Apple", "Amazon", "Facebook", "Meta", "Oracle", "IBM",
    "CISA", "FBI", "NSA", "United States", "US", "U.S.", "UK", "UK's", "Russia", "China",
    "Iran", "JetBrains", "SolarWinds", "Zabbix", "Webroot", "Dropbox", "OneDrive",
    "SQL Server", "Visual Studio", "Windows", "Office", "Symantec", "Broadcom",
    "Deep Instinct", "CrowdStrike", "Mandiant", "Recorded Future", "Palo Alto Networks",
    "CERT", "NCSC", "SKW", "Golo M\u00fchr", "Claire Zaboeva", "Joe Fasulo",
    "IBM Security Intelligence", "X-Force", "IBM X-Force",
}

CTI_KEYWORDS = {
    "malware", "backdoor", "exploit", "cyber", "attack", "campaign", "group",
    "threat", "actor", "hacking", "vulnerability", "cve", "payload", "stager",
    "dropper", "phishing", "breach", "compromise", "espionage",
}

# ── Regex patterns ─────────────────────────────────────────────────────────────
IP_REGEX = r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b"

DOMAIN_REGEX = (
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\[\.\]|\.))"
    r"+(?:com|net|org|io|ru|xyz|top|cloud|online|support|info|biz|site|"
    r"app|tech|co|uk|de|fr|nl|gov|edu|mil|mobi|int)\b"
)

URL_REGEX = r"(?:hxxps?|https?)://[^\s\"<>,;\n]+"

HASH_SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"
HASH_SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
HASH_MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
HASH_REGEXES = (HASH_SHA256_REGEX, HASH_SHA1_REGEX, HASH_MD5_REGEX)

CVE_REGEX = r"\bCVE-\d{4}-\d{4,7}\b"
TTP_REGEX = r"\bT\d{4}(?:\.\d{3})?\b"
EMAIL_REGEX = r"[a-zA-Z0-9._%+\-]+@(?:[a-zA-Z0-9\-]+(?:\[\.\]|\.))+[a-zA-Z]{2,}"
BTC_REGEX = r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{6,87}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"

THREAT_ACTOR_REGEX = (
    r"\b(?:TA\s*-\s*[A-Z][a-zA-Z0-9]+|FIN\s*\d+|APT\s*\d+|UNC\s*-\s*\d+|LAPSUS\$?"
    r"|Lazarus(?:\s+Group)?|Sandworm|Fancy\s+Bear|Cozy\s*Bear|Turla|Kimsuky"
    r"|LockBit|BlackCat|ALPHV|REvil|DarkSide|Conti|Hive|TA-505"
    r"|ShadowForge|UNC-2147|SVR|NOBELIUM|Midnight\s+Blizzard|The\s+Dukes"
    r"|Pawn\s+Storm|Voodoo\s+Bear|Iron\s+Twilight|ITG05|UAC-028|Forest\s+Blizzard"
    r"|MuddyWater|Diplomatic\s+Orbiter)\b"
)

MALWARE_REGEX = (
    r"\b(?:RedLine|Emotet|Cobalt\s+Strike|Sliver|Mimikatz|Metasploit"
    r"|PowerShell\s+Empire|TrickBot|AgentTesla|AsyncRAT|NjRAT|QuasarRAT"
    r"|BlackCat|ALPHV|LockBit|Ryuk|Conti|REvil|Hive|NetSupportRAT"
    r"|IcedID|Qakbot|Dridex|Raccoon|Vidar|FormBook|GuLoader"
    r"|ShadowLoader|SfLoader|WellMess|WellMail|Sorefang|GraphicalProton"
    r"|EDRSandBlast|SharpChromium|Rubeus|PowerSploit|WinPEAS"
    r"|Headlace|Headlace\s+backdoor|Steal-It|Graphite|Credomap|Rsockstun)\b"
)

REGISTRY_REGEX = r"\bHK(?:CU|LM|CR|U|CC)\\[^\s,\"';\n]+"
MUTEX_REGEX = r"\bGlobal\\\\[^\s,\"';\n]+"
UA_REGEX = r"Mozilla/[\d.]+\s*\([^)]+\)(?:\s+[^\s,\n\"]+)*"

# output.json field → (pattern, regex flags)
IOC_PATTERNS: dict[str, tuple[str, int]] = {
    "ips": (IP_REGEX, 0),
    "domains": (DOMAIN_REGEX, 0),
    "urls": (URL_REGEX, 0),
    "cves": (CVE_REGEX, 0),
    "ttps": (TTP_REGEX, 0),
    "emails": (EMAIL_REGEX, 0),
    "mutexes": (MUTEX_REGEX, 0),
    "user_agents": (UA_REGEX, 0),
}

ACTOR_LABELS = frozenset({"ORG", "PERSON"})
MALWARE_LABELS = frozenset({"PRODUCT"})
OTHER_ENTITY_LABELS = frozenset({"GPE", "LOC", "NORP", "EVENT", "WORK_OF_ART"})
