import json
import re
from pathlib import Path

import spacy

from .chains import run_llm_analysis
from .helpers import classify_hash, find_all
from .patterns import (
    BENIGN_ORGS,
    BTC_REGEX,
    CTI_KEYWORDS,
    CVE_REGEX,
    DOMAIN_REGEX,
    EMAIL_REGEX,
    HASH_MD5_REGEX,
    HASH_SHA1_REGEX,
    HASH_SHA256_REGEX,
    IP_REGEX,
    MALWARE_REGEX,
    MUTEX_REGEX,
    REGISTRY_REGEX,
    THREAT_ACTOR_REGEX,
    TTP_REGEX,
    UA_REGEX,
    URL_REGEX,
)

nlp = spacy.load("en_core_web_sm")


def has_cti_context(ent, doc, window=15) -> bool:
    """Check if CTI-related keywords are near the entity."""
    start = max(0, ent.start - window)
    end = min(len(doc), ent.end + window)
    context_tokens = [t.text.lower() for t in doc[start:end]]
    return any(kw in context_tokens for kw in CTI_KEYWORDS)


def extract_cti(src: str) -> dict:
    known_actors = find_all(THREAT_ACTOR_REGEX, src, re.IGNORECASE)
    known_malware = find_all(MALWARE_REGEX, src, re.IGNORECASE)

    raw_hashes = (
        find_all(HASH_SHA256_REGEX, src)
        + find_all(HASH_SHA1_REGEX, src)
        + find_all(HASH_MD5_REGEX, src)
    )
    hashes = [
        {"hash": h, "type": classify_hash(h)}
        for h in sorted(set(raw_hashes))
    ]

    doc = nlp(src)
    unknown_actors: list[str] = []
    unknown_malware: list[str] = []
    other_entities: list[dict] = []

    def is_known(txt: str) -> bool:
        return bool(
            re.search(THREAT_ACTOR_REGEX, txt, re.I)
            or re.search(MALWARE_REGEX, txt, re.I)
        )

    for ent in doc.ents:
        entity_text = ent.text.strip()
        label = ent.label_

        if entity_text in BENIGN_ORGS or is_known(entity_text):
            continue

        if label in {"ORG", "PERSON"} and has_cti_context(ent, doc):
            unknown_actors.append(entity_text)
        elif label == "PRODUCT" and has_cti_context(ent, doc):
            unknown_malware.append(entity_text)
        elif label in {"GPE", "LOC", "NORP", "EVENT", "WORK_OF_ART"}:
            other_entities.append({"text": entity_text, "label": label})

    print("\n[+] Running LangChain Threat Actor Analysis...")
    llm_result = run_llm_analysis(src)
    llm_actors = llm_result["actors"]
    llm_malware = llm_result["malware"]
    llm_summary = llm_result["summary"]

    final_actors = sorted(set(known_actors + unknown_actors + llm_actors))
    final_malware = sorted(set(known_malware + unknown_malware + llm_malware))

    return {
        "summary": llm_summary,
        "ips": find_all(IP_REGEX, src),
        "domains": find_all(DOMAIN_REGEX, src),
        "urls": find_all(URL_REGEX, src),
        "hashes": hashes,
        "cves": find_all(CVE_REGEX, src),
        "ttps": find_all(TTP_REGEX, src),
        "emails": find_all(EMAIL_REGEX, src),
        "bitcoin_wallets": find_all(BTC_REGEX, src),
        "threat_actors": {
            "known": known_actors,
            "spacy_detected": sorted(set(unknown_actors)),
            "llm_detected": llm_actors,
            "final": final_actors,
        },
        "malware": {
            "known": known_malware,
            "spacy_detected": sorted(set(unknown_malware)),
            "llm_detected": llm_malware,
            "final": final_malware,
        },
        "registry_keys": find_all(REGISTRY_REGEX, src),
        "mutexes": find_all(MUTEX_REGEX, src),
        "user_agents": find_all(UA_REGEX, src),
        "other_entities": sorted(
            {e["text"]: e for e in other_entities}.values(),
            key=lambda x: x["text"],
        ),
    }


if __name__ == "__main__":
    app_dir = Path(__file__).parent
    text = app_dir.joinpath("report.txt").read_text(encoding="utf-8")
    output = extract_cti(text)

    output_path = app_dir.joinpath("output.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)

    print("\n[✓] Extraction Complete")
    print(f"[✓] Results saved to: {output_path}")
