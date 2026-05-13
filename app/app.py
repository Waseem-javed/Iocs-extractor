import json
import spacy
from pathlib import Path

from .patterns import (
    IP_REGEX, DOMAIN_REGEX, URL_REGEX, HASH_SHA256_REGEX, HASH_SHA1_REGEX,
    HASH_MD5_REGEX, CVE_REGEX, TTP_REGEX, EMAIL_REGEX, BTC_REGEX,
    THREAT_ACTOR_REGEX, MALWARE_REGEX, REGISTRY_REGEX, MUTEX_REGEX, UA_REGEX
)

from .helpers import (
    find_all,
    classify_hash
)

# ── Load Input ────────────────────────────────────────────────────────────────
text = Path(__file__).parent.joinpath("report.txt").read_text(encoding="utf-8")

# ── Load spaCy Model (CPU-only) ───────────────────────────────────────────────
nlp = spacy.load("en_core_web_sm")

# ── Core Extractor ────────────────────────────────────────────────────────────

def extract_cti(src: str) -> dict:
    # Collect all hashes and tag by type
    raw_hashes = find_all(HASH_SHA256_REGEX, src) + \
                 find_all(HASH_SHA1_REGEX, src) + \
                 find_all(HASH_MD5_REGEX, src)
    hashes = [{"hash": h, "type": classify_hash(h)} for h in sorted(set(raw_hashes))]

    result = {
        "ips":            find_all(IP_REGEX, src),
        "domains":        find_all(DOMAIN_REGEX, src),
        "urls":           find_all(URL_REGEX, src),
        "hashes":         hashes,
        "cves":           find_all(CVE_REGEX, src),
        "ttps":           find_all(TTP_REGEX, src),
        "emails":         find_all(EMAIL_REGEX, src),
        "bitcoin_wallets":find_all(BTC_REGEX, src),
        "threat_actors":  find_all(THREAT_ACTOR_REGEX, src),
        "malware":        find_all(MALWARE_REGEX, src),
        "registry_keys":  find_all(REGISTRY_REGEX, src),
        "mutexes":        find_all(MUTEX_REGEX, src),
        "user_agents":    find_all(UA_REGEX, src),
        "entities":       [],
    }

    # spaCy NER — deduplicated, filtered to CTI-relevant labels
    RELEVANT_LABELS = {"ORG", "GPE", "LOC", "PERSON", "NORP", "PRODUCT", "EVENT", "WORK_OF_ART"}
    doc = nlp(src)
    seen: set[tuple] = set()
    for ent in doc.ents:
        if ent.label_ in RELEVANT_LABELS:
            key = (ent.text.strip(), ent.label_)
            if key not in seen:
                seen.add(key)
                result["entities"].append({"text": ent.text.strip(), "label": ent.label_})

    return result


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    output = extract_cti(text)
    print(json.dumps(output, indent=2))