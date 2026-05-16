import json
import re
from pathlib import Path

import spacy

from .chains import run_llm_analysis
from .helpers import (
    entity_bucket,
    extract_hashes,
    extract_iocs,
    filter_bitcoin_wallets,
    find_all,
    is_spurious_entity,
    is_valid_registry_key,
    matches_pattern,
    overlaps_known_actor,
)
from .patterns import (
    ACTOR_LABELS,
    BENIGN_ORGS,
    BTC_REGEX,
    CTI_KEYWORDS,
    HASH_REGEXES,
    IOC_PATTERNS,
    MALWARE_LABELS,
    MALWARE_REGEX,
    OTHER_ENTITY_LABELS,
    REGISTRY_REGEX,
    THREAT_ACTOR_REGEX,
)

nlp = spacy.load("en_core_web_sm")
_I = re.IGNORECASE


def has_cti_context(ent, doc, window=15) -> bool:
    start = max(0, ent.start - window)
    end = min(len(doc), ent.end + window)
    tokens = {t.text.lower() for t in doc[start:end]}
    return bool(tokens & CTI_KEYWORDS)


def _is_known_entity(text: str) -> bool:
    return (
        matches_pattern(THREAT_ACTOR_REGEX, text)
        or matches_pattern(MALWARE_REGEX, text)
    )


def _extract_entities(doc, known_actors: list[str]) -> tuple[list[str], list[str], list[dict]]:
    unknown_actors: list[str] = []
    unknown_malware: list[str] = []
    other_entities: list[dict] = []

    for ent in doc.ents:
        text = ent.text.strip()
        if text in BENIGN_ORGS or _is_known_entity(text):
            continue

        label = ent.label_
        if not has_cti_context(ent, doc):
            if label in OTHER_ENTITY_LABELS:
                other_entities.append({"text": text, "label": label})
            continue

        if label in ACTOR_LABELS:
            if not is_spurious_entity(text) and not overlaps_known_actor(text, known_actors):
                unknown_actors.append(text)
        elif label in MALWARE_LABELS and not is_spurious_entity(text):
            unknown_malware.append(text)
        elif label in OTHER_ENTITY_LABELS:
            other_entities.append({"text": text, "label": label})

    return unknown_actors, unknown_malware, other_entities


def extract_cti(src: str) -> dict:
    known_actors = find_all(THREAT_ACTOR_REGEX, src, _I)
    known_malware = find_all(MALWARE_REGEX, src, _I)
    hashes = extract_hashes(src, HASH_REGEXES)
    hash_values = {h["hash"] for h in hashes}

    doc = nlp(src)
    unknown_actors, unknown_malware, other_entities = _extract_entities(doc, known_actors)

    print("\n[+] Running LangChain analysis...")
    llm = run_llm_analysis(src)

    iocs = extract_iocs(src, IOC_PATTERNS)
    registry_keys = [k for k in find_all(REGISTRY_REGEX, src) if is_valid_registry_key(k)]

    return {
        "summary": llm["summary"],
        **iocs,
        "hashes": hashes,
        "bitcoin_wallets": filter_bitcoin_wallets(find_all(BTC_REGEX, src), hash_values),
        "registry_keys": registry_keys,
        "threat_actors": entity_bucket(known_actors, unknown_actors, llm["actors"]),
        "malware": entity_bucket(known_malware, unknown_malware, llm["malware"]),
        "other_entities": sorted(
            {e["text"]: e for e in other_entities}.values(),
            key=lambda e: e["text"],
        ),
    }


if __name__ == "__main__":
    app_dir = Path(__file__).parent
    text = (app_dir / "report.txt").read_text(encoding="utf-8")
    output_path = app_dir / "output.json"
    output_path.write_text(
        json.dumps(extract_cti(text), indent=2),
        encoding="utf-8",
    )
    print("\n[✓] Extraction complete")
    print(f"[✓] Results saved to: {output_path}")
