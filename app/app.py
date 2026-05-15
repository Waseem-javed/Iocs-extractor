import re
import json
import spacy
from pathlib import Path

from .patterns import (
    BENIGN_ORGS, CTI_KEYWORDS, IP_REGEX, DOMAIN_REGEX, URL_REGEX, 
    HASH_SHA256_REGEX, HASH_SHA1_REGEX, HASH_MD5_REGEX, CVE_REGEX, 
    TTP_REGEX, EMAIL_REGEX, BTC_REGEX, THREAT_ACTOR_REGEX, MALWARE_REGEX, 
    REGISTRY_REGEX, MUTEX_REGEX, UA_REGEX
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

def has_cti_context(ent, doc, window=15) -> bool:
    """Check if keywords are near the entity in the text."""
    start = max(0, ent.start - window)
    end = min(len(doc), ent.end + window)
    context_tokens = [t.text.lower() for t in doc[start:end]]
    return any(kw in context_tokens for kw in CTI_KEYWORDS)

def extract_cti(src: str) -> dict:
    # 1. Regex-based extraction (Known)
    known_actors = find_all(THREAT_ACTOR_REGEX, src, re.IGNORECASE)
    known_malware = find_all(MALWARE_REGEX, src, re.IGNORECASE)

    # Collect all hashes and tag by type
    raw_hashes = find_all(HASH_SHA256_REGEX, src) + \
                 find_all(HASH_SHA1_REGEX, src) + \
                 find_all(HASH_MD5_REGEX, src)
    hashes = [{"hash": h, "type": classify_hash(h)} for h in sorted(set(raw_hashes))]

    # 2. NER-based extraction (Potential Unknowns)
    doc = nlp(src)
    unknown_actors = []
    unknown_malware = []
    other_entities = []

    # Helper to check if text matches known regexes
    def is_known(txt):
        return any(re.search(THREAT_ACTOR_REGEX, txt, re.I) for _ in [1]) or \
               any(re.search(MALWARE_REGEX, txt, re.I) for _ in [1])

    for ent in doc.ents:
        text = ent.text.strip()
        label = ent.label_

        if text in BENIGN_ORGS or is_known(text):
            continue

        # Intelligent candidate selection using context
        if label in {"ORG", "PERSON"}:
            if not any(re.search(THREAT_ACTOR_REGEX, text, re.I) for _ in [1]):
                # If it's a person/org and near CTI keywords, it's an 'unknown actor'
                if has_cti_context(ent, doc):
                    unknown_actors.append(text)
        elif label == "PRODUCT":
            if not any(re.search(MALWARE_REGEX, text, re.I) for _ in [1]):
                if has_cti_context(ent, doc):
                    unknown_malware.append(text)
        elif label in {"GPE", "LOC", "NORP", "EVENT", "WORK_OF_ART"}:
            other_entities.append({"text": text, "label": label})

    result = {
        "ips":            find_all(IP_REGEX, src),
        "domains":        find_all(DOMAIN_REGEX, src),
        "urls":           find_all(URL_REGEX, src),
        "hashes":         hashes,
        "cves":           find_all(CVE_REGEX, src),
        "ttps":           find_all(TTP_REGEX, src),
        "emails":         find_all(EMAIL_REGEX, src),
        "bitcoin_wallets":find_all(BTC_REGEX, src),
        "threat_actors": {
            "known": known_actors,
            "unknown": sorted(set(unknown_actors))
        },
        "malware": {
            "known": known_malware,
            "unknown": sorted(set(unknown_malware))
        },
        "registry_keys":  find_all(REGISTRY_REGEX, src),
        "mutexes":        find_all(MUTEX_REGEX, src),
        "user_agents":    find_all(UA_REGEX, src),
        "other_entities": sorted({e["text"]: e for e in other_entities}.values(), key=lambda x: x["text"]),
    }

    return result


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    output = extract_cti(text)
    
    # Define output path (same directory as app.py)
    output_path = Path(__file__).parent.joinpath("output.json")
    
    # Save to file (overwrites existing)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    
    print(f"Extraction complete. Results saved to: {output_path}")