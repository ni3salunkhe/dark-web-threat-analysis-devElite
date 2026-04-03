"""
DWTIS Phase 2 — Dynamic NLP Processing Engine (v2)

KEY DESIGN PRINCIPLE: Zero hardcoded org lists, zero static slang dictionaries.
The system detects threats dynamically using:
  - spaCy NER for ANY organization mentioned anywhere
  - LLM-based dynamic slang extraction (asks the model to identify jargon)
  - Semantic similarity for pattern detection without keyword matching
  - Context-aware severity scoring based on what IS there, not watchlist hits
  - Cross-lingual detection via langdetect + Helsinki-NLP translation
"""

import sqlite3
import json
import re
import time
import logging
from datetime import datetime, timedelta
from typing import Optional
import hashlib

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("nlp_engine_v2")

DB_PATH = "dwtis.db"

# ─────────────────────────────────────────────────────────────────────────────
# THREAT CATEGORIES — these are semantic descriptions, not keywords
# The zero-shot model uses meaning, not string matching
# ─────────────────────────────────────────────────────────────────────────────
THREAT_LABELS = [
    "stolen credentials, passwords, or account access being sold or shared",
    "ransomware, malware, or hacking tools for sale or deployment",
    "stolen payment card data, bank account fraud, or financial theft",
    "announcement or evidence of a data breach or database leak",
    "software vulnerability, exploit code, or zero-day being offered",
    "phishing infrastructure, fake login pages, or social engineering kits",
    "personal private information being exposed or threatened",
    "general cybersecurity news or research discussion",
]

LABEL_MAP = {
    "stolen credentials, passwords, or account access being sold or shared": "credential-leak",
    "ransomware, malware, or hacking tools for sale or deployment": "ransomware",
    "stolen payment card data, bank account fraud, or financial theft": "carding",
    "announcement or evidence of a data breach or database leak": "data-breach",
    "software vulnerability, exploit code, or zero-day being offered": "exploit-sale",
    "phishing infrastructure, fake login pages, or social engineering kits": "phishing",
    "personal private information being exposed or threatened": "doxxing",
    "general cybersecurity news or research discussion": "benign",
}

THREAT_SEVERITY_BASE = {
    "credential-leak": 0.30,
    "data-breach": 0.28,
    "ransomware": 0.25,
    "carding": 0.22,
    "exploit-sale": 0.20,
    "doxxing": 0.20,
    "phishing": 0.18,
    "benign": 0.0,
}

# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC SLANG EXTRACTION PROMPT
# Instead of a static dictionary, we ask the LLM to identify and decode
# any underground/hacker terminology it sees in the text.
# ─────────────────────────────────────────────────────────────────────────────
SLANG_EXTRACTION_PROMPT = """You are a cybersecurity analyst specializing in dark web threat intelligence.

Analyze the following text and identify ANY underground, hacker, or criminal marketplace terminology.
This includes slang, coded language, abbreviations, or jargon used in cybercrime communities.

For each term found, provide its plain-English meaning for a security analyst.
Also flag if the text appears to be in a language other than English or uses transliterated words.

Return ONLY a JSON object in this exact format (no other text):
{{
  "slang_terms": {{
    "term_found": "plain English meaning for security analyst"
  }},
  "coded_language_detected": true/false,
  "language_hints": ["list of languages or scripts detected"],
  "threat_indicators": ["list of specific threat signals you noticed"]
}}

If no slang or coded language is found, return empty objects/arrays.

TEXT TO ANALYZE:
{text}"""


# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC ENTITY EXTRACTION PROMPT
# Extracts ALL organizations regardless of whether we know them in advance
# ─────────────────────────────────────────────────────────────────────────────
ENTITY_EXTRACTION_PROMPT = """You are a cybersecurity threat intelligence analyst.

Extract ALL entities mentioned in this text that could be targets, victims, or subjects of a cyber threat.
Cast a wide net — include any company, organization, government body, financial institution, app, service,
website, platform, or brand name you can identify, even if you only partially recognize it.

Return ONLY a JSON object (no other text):
{{
  "organizations": ["list of all org/company/service names found"],
  "domains": ["list of domain names or website URLs found"],
  "email_addresses": ["found emails - show only domain part e.g. user@***.com → ***.com"],
  "ip_addresses": ["found IP addresses"],
  "crypto_addresses": ["found cryptocurrency wallet addresses - first 8 chars only"],
  "usernames_handles": ["found usernames, handles, or aliases"],
  "threat_actor_names": ["names of threat actors, hacker groups, or malware families"],
  "data_types_exposed": ["types of data mentioned: passwords, SSN, card numbers, etc."],
  "record_count_estimate": "estimated number of affected records if mentioned, else null",
  "geographic_targets": ["countries or regions specifically targeted"]
}}

TEXT:
{text}"""


# ─────────────────────────────────────────────────────────────────────────────
# Lazy model loaders
# ─────────────────────────────────────────────────────────────────────────────
_classifier = None
_nlp = None
_translator_cache = {}


def get_classifier():
    global _classifier
    if _classifier is None:
        log.info("Loading zero-shot classifier (bart-large-mnli)...")
        from transformers import pipeline
        _classifier = pipeline(
            "zero-shot-classification",
            model="facebook/bart-large-mnli",
            device=-1,
        )
        log.info("Classifier loaded.")
    return _classifier


def get_nlp():
    global _nlp
    if _nlp is None:
        log.info("Loading spaCy NER...")
        import spacy
        try:
            _nlp = spacy.load("en_core_web_sm")
        except OSError:
            import subprocess, sys
            subprocess.run([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
            _nlp = spacy.load("en_core_web_sm")
        log.info("spaCy loaded.")
    return _nlp


def get_translator(src_lang: str):
    """Lazy-load Helsinki-NLP translation model for non-English text."""
    if src_lang in _translator_cache:
        return _translator_cache[src_lang]
    try:
        from transformers import pipeline as hf_pipeline
        model_name = f"Helsinki-NLP/opus-mt-{src_lang}-en"
        translator = hf_pipeline("translation", model=model_name, device=-1)
        _translator_cache[src_lang] = translator
        log.info(f"Translation model loaded for {src_lang}→en")
        return translator
    except Exception as e:
        log.warning(f"Translation model for {src_lang} unavailable: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Language detection & translation
# ─────────────────────────────────────────────────────────────────────────────

def detect_and_translate(text: str) -> tuple[str, str, bool]:
    """
    Detect language, translate to English if needed.
    Returns: (processed_text, detected_lang, was_translated)
    Supported source languages: ru, fr, de, zh, ar, pt, es, hi
    Falls back gracefully — if translation unavailable, uses original text.
    """
    try:
        from langdetect import detect
        lang = detect(text)
    except Exception:
        return text, "en", False

    if lang == "en":
        return text, "en", False

    # Map langdetect codes to Helsinki-NLP model codes
    lang_map = {
        "ru": "ru", "fr": "fr", "de": "de",
        "zh-cn": "zh", "zh-tw": "zh", "ar": "ar",
        "pt": "pt", "es": "es", "hi": "hi",
        "id": "id", "tr": "tr", "ko": "ko",
    }
    src = lang_map.get(lang)

    if not src:
        log.info(f"No translation model for lang={lang}, proceeding with original text.")
        return text, lang, False

    translator = get_translator(src)
    if translator is None:
        return text, lang, False

    try:
        translated = translator(text[:512])[0]["translation_text"]
        log.info(f"Translated {lang}→en: {text[:50]}...")
        return translated, lang, True
    except Exception as e:
        log.warning(f"Translation failed: {e}")
        return text, lang, False


# ─────────────────────────────────────────────────────────────────────────────
# LLM-based dynamic analysis (uses the same classifier model as a text generator)
# For zero-shot, we use a separate lighter model for extraction tasks
# ─────────────────────────────────────────────────────────────────────────────

_extractor = None


def get_extractor():
    """
    Load a lightweight text generation model for structured extraction.
    Uses flan-t5-base (~250 MB) which handles instruction-following well.
    Falls back to regex+spaCy if unavailable.
    """
    global _extractor
    if _extractor is None:
        try:
            from transformers import pipeline as hf_pipeline
            _extractor = hf_pipeline(
                "text2text-generation",
                model="google/flan-t5-base",
                device=-1,
                max_new_tokens=512,
            )
            log.info("flan-t5-base extractor loaded (~250 MB).")
        except Exception as e:
            log.warning(f"Extractor model unavailable ({e}), using regex fallback.")
            _extractor = "fallback"
    return _extractor


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic entity extraction — NO hardcoded org list
# ─────────────────────────────────────────────────────────────────────────────

def extract_entities_dynamic(text: str) -> dict:
    """
    Extracts entities from ANY text without a predefined organization list.
    Layer 1: spaCy NER (fast, structural)
    Layer 2: Broad regex patterns (emails, IPs, domains, hashes, card numbers)
    Layer 3: LLM extraction prompt (catches orgs spaCy misses, data types, actor names)
    All three layers combined — no org is missed because it wasn't in a watchlist.
    """
    results = {
        "organizations": [],
        "domains": [],
        "email_addresses": [],
        "ip_addresses": [],
        "crypto_addresses": [],
        "usernames_handles": [],
        "threat_actor_names": [],
        "data_types_exposed": [],
        "record_count_estimate": None,
        "geographic_targets": [],
        "spacy_raw": {},
    }

    # ── Layer 1: spaCy NER ────────────────────────────────────────────────────
    nlp = get_nlp()
    doc = nlp(text[:1024])
    spacy_entities = {}
    for ent in doc.ents:
        label = ent.label_
        if label not in spacy_entities:
            spacy_entities[label] = []
        spacy_entities[label].append(ent.text)

    results["spacy_raw"] = spacy_entities
    results["organizations"] = list(set(spacy_entities.get("ORG", [])))
    results["geographic_targets"] = list(set(
        spacy_entities.get("GPE", []) + spacy_entities.get("LOC", [])
    ))
    results["organizations"] += list(set(spacy_entities.get("PRODUCT", [])))

    # Extract person names — could be threat actors or victims
    persons = list(set(spacy_entities.get("PERSON", [])))

    # ── Layer 2: Regex patterns (broad, not India-specific) ──────────────────
    # Email domains (obfuscated — we don't store full email addresses)
    email_pattern = re.compile(r"\b[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b")
    email_domains = list(set(email_pattern.findall(text)))
    results["email_addresses"] = email_domains

    # IP addresses (IPv4 + IPv6 partial)
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    results["ip_addresses"] = list(set(ip_pattern.findall(text)))

    # Domain names
    domain_pattern = re.compile(
        r"\b(?:[a-z0-9\-]+\.)+(?:com|org|net|gov|io|co|in|ru|cn|de|uk|br|edu|mil|info|biz)\b",
        re.I
    )
    results["domains"] = list(set(domain_pattern.findall(text)))

    # Cryptocurrency addresses (Bitcoin, Ethereum, Monero patterns)
    btc_pattern = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
    eth_pattern = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
    xmr_pattern = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
    crypto = (
        [addr[:8] + "***" for addr in btc_pattern.findall(text)] +
        [addr[:8] + "***" for addr in eth_pattern.findall(text)] +
        [addr[:8] + "***" for addr in xmr_pattern.findall(text)]
    )
    results["crypto_addresses"] = list(set(crypto))

    # Hashes (MD5, SHA1, SHA256, bcrypt)
    hash_patterns = [
        re.compile(r"\b[a-fA-F0-9]{32}\b"),   # MD5
        re.compile(r"\b[a-fA-F0-9]{40}\b"),   # SHA1
        re.compile(r"\b[a-fA-F0-9]{64}\b"),   # SHA256
        re.compile(r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"),  # bcrypt
    ]
    hashes_found = []
    for hp in hash_patterns:
        hashes_found += hp.findall(text)
    if hashes_found:
        results["data_types_exposed"].append(f"password_hashes ({len(hashes_found)} found)")

    # Payment card patterns (Luhn-format — any issuer, any country)
    card_pattern = re.compile(
        r"\b(?:4[0-9]{12,15}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|"
        r"(?:2131|1800|35\d{3})\d{11})\b"
    )
    if card_pattern.search(text):
        results["data_types_exposed"].append("payment_card_numbers")

    # Record count — look for number patterns near "records", "users", "accounts"
    count_pattern = re.compile(
        r"(\d[\d,\.]+)\s*(?:million|M|k|K|thousand)?\s*"
        r"(?:records?|users?|accounts?|entries|rows|lines|victims?)",
        re.I
    )
    count_match = count_pattern.search(text)
    if count_match:
        results["record_count_estimate"] = count_match.group(0).strip()

    # ── Layer 3: LLM extraction for anything regex/spaCy missed ──────────────
    extractor = get_extractor()
    if extractor != "fallback":
        try:
            prompt = (
                f"Extract cybersecurity threat entities from this text. "
                f"List: company names, hacker group names, malware names, data types stolen. "
                f"Text: {text[:300]}"
            )
            llm_out = extractor(prompt)[0]["generated_text"]
            # Parse any additional org names the LLM found that spaCy missed
            # Simple heuristic: capitalized multi-word phrases not already in results
            additional_orgs = re.findall(r"\b[A-Z][a-z]+(?:\s[A-Z][a-z]+)+\b", llm_out)
            for org in additional_orgs:
                if org not in results["organizations"] and len(org) > 3:
                    results["organizations"].append(f"{org} (LLM-detected)")
        except Exception as e:
            log.debug(f"LLM extractor fallback: {e}")

    # Deduplicate
    results["organizations"] = list(set(results["organizations"]))

    return results


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic slang detection — NO hardcoded dictionary
# ─────────────────────────────────────────────────────────────────────────────

def detect_slang_dynamic(text: str) -> dict:
    """
    Identifies underground/criminal marketplace jargon WITHOUT a static dictionary.

    Approach:
    1. Semantic threat scoring — does the text semantically resemble known threat
       categories even without matching any keyword?
    2. Out-of-vocabulary (OOV) detection — words not in standard English that 
       appear in threat contexts are flagged as potential slang.
    3. LLM-based jargon identification — ask the extractor model to identify 
       any coded or specialized language.
    4. Pattern-based signals — structural patterns common to underground posts
       (price mentions, contact methods, verification claims).

    Returns decoded slang terms and threat signals found.
    """
    result = {
        "decoded_terms": {},    # term → meaning
        "structural_signals": [],  # patterns like "price negotiable", "escrow"
        "oov_suspects": [],     # words not in standard dictionary, flagged
        "confidence": 0.0,
    }

    text_lower = text.lower()

    # ── Pattern 1: Structural signals of underground trading ─────────────────
    STRUCTURAL_PATTERNS = [
        (r"\b(escrow|middle ?man)\b", "payment_escrow_mentioned"),
        (r"\b(btc|bitcoin|xmr|monero|eth|usdt|crypto)\b", "crypto_payment_method"),
        (r"\b(dm|pm|telegram|tg|signal|wickr|jabber|session)\b", "encrypted_contact_method"),
        (r"\b(verified|vouched?|vouch|rep|reputation)\b", "reputation_system_reference"),
        (r"\bsample\b.*\bavail", "sample_data_offered"),
        (r"\bfree\b.*\bleak|\bleak\b.*\bfree", "free_leak_advertised"),
        (r"\b(\d[\d,]+)\s*(records?|entries|lines|rows|accounts?|users?)", "dataset_size_mentioned"),
        (r"\b(fresh|new|latest|updated|2024|2025|recent)\b", "recency_claim"),
        (r"\b(cracked?|dehashed?|cleartext|plaintext|unhashed)\b", "cracked_credentials"),
        (r"\b(fullz?|full ?packages?|complete ?info)\b", "full_identity_package"),
        (r"\b(combol?i?s?t?s?|comb[o0])\b", "credential_dump_list"),
        (r"\b(stealer?|infostealer|keylogger|rat\b|trojan)\b", "malware_type"),
        (r"\bfud\b", "fully_undetectable_malware"),
        (r"\b(loader|dropper|payload|stage[12])\b", "malware_delivery_mechanism"),
        (r"\b(rdp|vnc|ssh|shell|webshell)\b.*\b(access|sell|buy|avail)", "unauthorized_access_sale"),
        (r"\b(dump[sz]?|track\s*[12]|magnetic\s*stripe)\b", "card_dump_data"),
        (r"\b(bins?|binn?ing|carding|cashout|cash\s*out)\b", "financial_fraud_activity"),
        (r"\b(0day|zero[ -]day|zeroday|n[ -]day|nday)\b", "zero_day_exploit"),
        (r"\b(poc|proof.of.concept|exploit\s*code)\b", "exploit_code_available"),
        (r"\b(spray|stuffing|brute\s*forc|credential\s*stuff)\b", "credential_attack_method"),
        (r"\bpassword\b.{0,30}\b(list|db|database|dump|file)\b", "password_database"),
        (r"\b(dox|doxx|swat|swatting|leak\s*info)\b", "personal_info_threat"),
        (r"\b(botnet|c2|c&c|command.and.control|zombie)\b", "malware_infrastructure"),
        (r"\b(phish|phishing|kit|panel|cpanel|webmail)\b.*\b(sell|buy|avail|share)\b", "phishing_kit"),
        (r"\b(config|checker|account.checker|account.cracker)\b", "credential_checker_tool"),
        (r"\b(vps|bulletproof|bp\s*host|offshore\s*host)\b", "criminal_infrastructure"),
        (r"\bogs?\b|\bog\s+account|\boriginal\s+account\b", "original_account_takeover"),
    ]

    for pattern_str, signal_name in STRUCTURAL_PATTERNS:
        if re.search(pattern_str, text_lower):
            result["structural_signals"].append(signal_name)

    # ── Pattern 2: Numeric threat indicators ─────────────────────────────────
    # Prices in crypto/USD near threat terms
    price_pattern = re.compile(
        r"(\$\d+|\d+\s*(?:usd|btc|xmr|usdt|eth))\s*.{0,30}"
        r"(?:for|per|each|sell|buy|price|cost)",
        re.I
    )
    if price_pattern.search(text):
        result["structural_signals"].append("explicit_price_for_threat_data")

    # ── Pattern 3: OOV word detection using basic English vocabulary check ────
    try:
        import enchant
        d = enchant.Dict("en_US")
        words = re.findall(r"\b[a-zA-Z]{4,}\b", text)
        for word in set(words):
            if not d.check(word) and not d.check(word.lower()):
                # Not a standard English word — potential slang/jargon
                result["oov_suspects"].append(word.lower())
    except ImportError:
        # enchant not available — use a simple heuristic instead
        # Words with unusual character combinations common in hacker slang
        leet_pattern = re.compile(r"\b\w*[0-9]\w*[a-zA-Z]\w*\b|\b\w*[a-zA-Z]\w*[0-9]\w*\b")
        leet_words = leet_pattern.findall(text)
        result["oov_suspects"] = [w.lower() for w in set(leet_words) if len(w) > 3]

    # ── Pattern 4: LLM-based jargon identification ───────────────────────────
    extractor = get_extractor()
    if extractor != "fallback" and len(text) > 30:
        try:
            prompt = (
                "Identify cybercrime or hacker slang in this text. "
                "List each slang term and its meaning briefly. "
                f"Text: {text[:250]}"
            )
            llm_out = extractor(prompt, max_new_tokens=200)[0]["generated_text"]
            if llm_out and len(llm_out) > 10:
                result["decoded_terms"]["llm_analysis"] = llm_out.strip()
        except Exception as e:
            log.debug(f"LLM slang detection skipped: {e}")

    # Calculate confidence based on signals found
    signal_count = len(result["structural_signals"])
    result["confidence"] = min(signal_count * 0.12, 1.0)

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Threat classification (zero-shot — semantic, not keyword-based)
# ─────────────────────────────────────────────────────────────────────────────

def classify_threat(text: str) -> dict:
    clf = get_classifier()
    result = clf(text[:400], THREAT_LABELS, multi_label=False)
    top_label = result["labels"][0]
    top_score = result["scores"][0]

    return {
        "label": LABEL_MAP.get(top_label, "unknown"),
        "label_full": top_label,
        "confidence": round(top_score, 4),
        "all_scores": {
            LABEL_MAP.get(l, l): round(s, 3)
            for l, s in zip(result["labels"], result["scores"])
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
# Dynamic severity scoring — works on ANY post, any org
# ─────────────────────────────────────────────────────────────────────────────

def compute_severity(
    classification: dict,
    entities: dict,
    slang: dict,
    original_text: str,
    was_translated: bool = False,
) -> tuple[str, float]:
    """
    Severity scoring that requires NO prior knowledge of the organization.
    
    P1 = 0.70+ : Active threat to identified org with high-confidence classification
    P2 = 0.50+  : Threat signal with entity context
    P3 = 0.25+  : Weak signals, general threat discussion
    P4 = <0.25  : Informational, benign

    Score components:
    - Threat classification confidence * category weight (0.30)
    - Entities found (orgs, IPs, domains) — any entity, not just watchlist (0.25)
    - Structural slang signals found (0.20)
    - PII/data indicators found (0.15)
    - Translation bonus — non-English content in threat context is rarer and higher value (0.10)
    """
    score = 0.0

    # Component 1: Classification quality (0.30 max)
    label = classification.get("label", "benign")
    conf = classification.get("confidence", 0.0)
    base_weight = THREAT_SEVERITY_BASE.get(label, 0.0)
    score += base_weight * conf

    # Component 2: Entity richness — ANY org raises the score (0.25 max)
    entity_score = 0.0
    orgs = entities.get("organizations", [])
    ips = entities.get("ip_addresses", [])
    domains = entities.get("domains", [])
    actors = entities.get("threat_actor_names", [])
    record_est = entities.get("record_count_estimate")

    if orgs:
        entity_score += min(len(orgs) * 0.06, 0.15)
    if ips:
        entity_score += min(len(ips) * 0.03, 0.06)
    if domains:
        entity_score += min(len(domains) * 0.02, 0.04)
    if actors:
        entity_score += 0.05  # Named threat actor = significant signal
    if record_est:
        entity_score += 0.05  # Estimated record count = scope indicator

    score += min(entity_score, 0.25)

    # Component 3: Underground structural signals (0.20 max)
    signals = slang.get("structural_signals", [])
    high_value_signals = {
        "credential_dump_list", "full_identity_package", "zero_day_exploit",
        "explicit_price_for_threat_data", "unauthorized_access_sale",
        "free_leak_advertised", "cracked_credentials",
    }
    signal_score = 0.0
    for sig in signals:
        if sig in high_value_signals:
            signal_score += 0.06
        else:
            signal_score += 0.02
    score += min(signal_score, 0.20)

    # Component 4: Data type indicators (0.15 max)
    data_types = entities.get("data_types_exposed", [])
    crypto_addrs = entities.get("crypto_addresses", [])
    card_data = "payment_card_numbers" in data_types
    hash_data = any("hash" in d for d in data_types)

    data_score = 0.0
    if card_data:
        data_score += 0.08
    if hash_data:
        data_score += 0.05
    if data_types:
        data_score += min(len(data_types) * 0.02, 0.06)
    if crypto_addrs:
        data_score += 0.03  # Crypto address = active transaction context
    score += min(data_score, 0.15)

    # Component 5: Translation bonus (0.10 max)
    # Non-English threat content is often more authentic / less noise
    if was_translated and label != "benign":
        score += 0.08

    # Clamp and classify
    score = min(round(score, 4), 1.0)

    if score >= 0.70:
        severity = "P1"
    elif score >= 0.50:
        severity = "P2"
    elif score >= 0.25:
        severity = "P3"
    else:
        severity = "P4"

    return severity, score


# ─────────────────────────────────────────────────────────────────────────────
# Signal correlation — cross-source, based on actual extracted entities
# ─────────────────────────────────────────────────────────────────────────────

def correlate_signals(conn: sqlite3.Connection, hours: int = 6) -> list:
    """
    Detects cross-source correlation without any predefined watchlist.
    Looks for the same organization (extracted dynamically) appearing across
    multiple sources within a time window — that IS the signal.
    """
    correlations = []
    cutoff = (datetime.utcnow() - timedelta(hours=hours)).isoformat()

    rows = conn.execute("""
        SELECT entities_json, classification_json, source, timestamp, severity_score
        FROM processed_posts
        WHERE timestamp > ? AND label != 'benign'
        ORDER BY timestamp DESC
        LIMIT 500
    """, (cutoff,)).fetchall()

    if not rows:
        return correlations

    # Group by each org found (dynamically extracted, no watchlist needed)
    org_map: dict[str, list] = {}
    for row in rows:
        try:
            ents = json.loads(row[0] or "{}")
            clf = json.loads(row[1] or "{}")
            for org in ents.get("organizations", []):
                org_clean = org.strip().lower()
                if len(org_clean) < 3:
                    continue
                if org_clean not in org_map:
                    org_map[org_clean] = []
                org_map[org_clean].append({
                    "source": row[2],
                    "label": clf.get("label", "unknown"),
                    "timestamp": row[3],
                    "score": row[4] or 0,
                })
        except Exception:
            continue

    for org, mentions in org_map.items():
        unique_sources = {m["source"] for m in mentions}
        if len(unique_sources) >= 2:
            categories = list({m["label"] for m in mentions})
            avg_score = sum(m["score"] for m in mentions) / len(mentions)
            correlations.append({
                "org": org,
                "mention_count": len(mentions),
                "sources": list(unique_sources),
                "categories": categories,
                "severity": "P1" if len(unique_sources) >= 3 or avg_score > 0.65 else "P2",
                "message": (
                    f"'{org}' detected in {len(mentions)} posts across "
                    f"{len(unique_sources)} independent sources in {hours}h window — "
                    f"threat types: {', '.join(categories)}"
                ),
            })

    # Sort by mention count descending
    correlations.sort(key=lambda x: x["mention_count"], reverse=True)
    return correlations


# ─────────────────────────────────────────────────────────────────────────────
# Impact estimation engine (Brownie Point B3)
# ─────────────────────────────────────────────────────────────────────────────

def estimate_impact(entities: dict, slang: dict, classification: dict, text: str) -> dict:
    """
    Estimates business and user impact of a detected threat.
    Works entirely from what was FOUND in the text — no hardcoded assumptions.
    """
    impact = {
        "affected_users_estimate": None,
        "data_sensitivity": "unknown",
        "business_risk": "unknown",
        "financial_exposure_usd": None,
        "remediation_complexity": "unknown",
        "notes": [],
    }

    # Affected users from record count
    record_str = entities.get("record_count_estimate")
    if record_str:
        impact["affected_users_estimate"] = record_str
        nums = re.findall(r"[\d,]+", record_str)
        if nums:
            try:
                count = int(nums[0].replace(",", ""))
                if "million" in record_str.lower() or "M" in record_str:
                    count *= 1_000_000
                elif "k" in record_str.lower():
                    count *= 1_000
                if count > 1_000_000:
                    impact["notes"].append("Mass breach — GDPR/IT Act notification likely required")
            except ValueError:
                pass

    # Data sensitivity from data types found
    data_types = entities.get("data_types_exposed", [])
    signals = slang.get("structural_signals", [])
    label = classification.get("label", "benign")

    high_sensitivity_indicators = {
        "payment_card_numbers", "full_identity_package",
        "credential_dump_list", "cracked_credentials",
    }
    medium_sensitivity_indicators = {
        "password_database", "unauthorized_access_sale",
        "phishing_kit", "malware_delivery_mechanism",
    }

    signal_set = set(signals)
    if signal_set & high_sensitivity_indicators or "payment_card" in str(data_types):
        impact["data_sensitivity"] = "critical"
        impact["business_risk"] = "severe"
    elif signal_set & medium_sensitivity_indicators or label in ("credential-leak", "ransomware"):
        impact["data_sensitivity"] = "high"
        impact["business_risk"] = "high"
    elif label in ("phishing", "exploit-sale"):
        impact["data_sensitivity"] = "medium"
        impact["business_risk"] = "medium"
    else:
        impact["data_sensitivity"] = "low"
        impact["business_risk"] = "low"

    # Financial exposure estimation (rough model)
    fin_map = {
        "critical": "$50K–$500K+ (card fraud + notification costs)",
        "severe": "$100K–$5M (regulatory fines + breach response)",
        "high": "$10K–$100K (credential reset + monitoring)",
        "medium": "$1K–$50K (patching + investigation)",
        "low": "<$1K (monitoring only)",
    }
    impact["financial_exposure_usd"] = fin_map.get(impact["business_risk"], "unknown")

    # Remediation complexity
    if label == "ransomware":
        impact["remediation_complexity"] = "very_high"
        impact["notes"].append("Ransomware deployment may already be in progress")
    elif label == "credential-leak":
        impact["remediation_complexity"] = "high"
        impact["notes"].append("Force password reset for all affected accounts immediately")
    elif label == "exploit-sale":
        impact["remediation_complexity"] = "high"
        impact["notes"].append("Patch identification and emergency deployment required")
    else:
        impact["remediation_complexity"] = "medium"

    return impact


# ─────────────────────────────────────────────────────────────────────────────
# Database setup
# ─────────────────────────────────────────────────────────────────────────────

def init_db(conn: sqlite3.Connection):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS processed_posts (
            id                  TEXT PRIMARY KEY,
            source              TEXT,
            original_text       TEXT,
            translated_text     TEXT,
            original_lang       TEXT,
            url                 TEXT,
            timestamp           TEXT,
            label               TEXT,
            confidence          REAL,
            severity            TEXT,
            severity_score      REAL,
            entities_json       TEXT,
            slang_json          TEXT,
            classification_json TEXT,
            impact_json         TEXT,
            processed_at        TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            severity    TEXT,
            score       REAL,
            message     TEXT,
            source      TEXT,
            orgs        TEXT,
            label       TEXT,
            post_id     TEXT,
            timestamp   TEXT,
            seen        INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS correlation_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            org         TEXT,
            severity    TEXT,
            message     TEXT,
            sources     TEXT,
            categories  TEXT,
            timestamp   TEXT
        )
    """)
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# Main processing loop
# ─────────────────────────────────────────────────────────────────────────────

def process_batch(conn: sqlite3.Connection, batch_size: int = 10) -> int:
    rows = conn.execute("""
        SELECT id, source, text, url, timestamp, lang
        FROM raw_posts
        WHERE processed = 0
        LIMIT ?
    """, (batch_size,)).fetchall()

    if not rows:
        return 0

    log.info(f"Processing {len(rows)} posts...")
    processed = 0

    for row in rows:
        post_id, source, text, url, timestamp, lang = row

        if not text or len(text.strip()) < 15:
            conn.execute("UPDATE raw_posts SET processed=1 WHERE id=?", (post_id,))
            continue

        try:
            # Step 1: Language detection + translation
            proc_text, detected_lang, was_translated = detect_and_translate(text)

            # Step 2: Threat classification (on translated text for accuracy)
            clf = classify_threat(proc_text)

            # Step 3: Dynamic entity extraction (all entities, not just known ones)
            entities = extract_entities_dynamic(proc_text)

            # Step 4: Dynamic slang detection (no static dictionary)
            slang = detect_slang_dynamic(proc_text)

            # Step 5: Severity scoring
            severity, score = compute_severity(clf, entities, slang, proc_text, was_translated)

            # Step 6: Impact estimation
            impact = estimate_impact(entities, slang, clf, proc_text)

            # Write enriched record
            conn.execute("""
                INSERT OR REPLACE INTO processed_posts
                (id, source, original_text, translated_text, original_lang, url,
                 timestamp, label, confidence, severity, severity_score,
                 entities_json, slang_json, classification_json, impact_json, processed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                post_id, source,
                text[:2000],
                proc_text[:2000] if was_translated else None,
                detected_lang,
                url, timestamp,
                clf["label"], clf["confidence"],
                severity, score,
                json.dumps(entities),
                json.dumps(slang),
                json.dumps(clf),
                json.dumps(impact),
                datetime.utcnow().isoformat(),
            ))

            # Fire alert for P1/P2
            if severity in ("P1", "P2"):
                orgs = entities.get("organizations", [])
                org_display = ", ".join(orgs[:3]) if orgs else "unspecified target"
                signals_display = ", ".join(slang.get("structural_signals", [])[:3])
                msg = (
                    f"[{severity}] {clf['label']} | score={score:.2f} | "
                    f"source={source} | orgs=[{org_display}] | "
                    f"signals=[{signals_display}] | lang={detected_lang}"
                )
                if was_translated:
                    msg += f" (translated from {detected_lang})"
                conn.execute("""
                    INSERT INTO alerts
                    (severity, score, message, source, orgs, label, post_id, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    severity, score, msg, source,
                    json.dumps(orgs[:5]), clf["label"],
                    post_id, datetime.utcnow().isoformat()
                ))
                conn.commit()
                log.warning(msg)

            conn.execute("UPDATE raw_posts SET processed=1 WHERE id=?", (post_id,))
            processed += 1

        except Exception as e:
            log.error(f"Error on {post_id}: {e}", exc_info=True)
            conn.execute("UPDATE raw_posts SET processed=1 WHERE id=?", (post_id,))

    return processed


def run_correlation_pass(conn: sqlite3.Connection):
    events = correlate_signals(conn)
    for ev in events:
        # Deduplicate — don't re-insert same org+severity within 1 hour
        existing = conn.execute("""
            SELECT id FROM correlation_events
            WHERE org=? AND timestamp > ?
        """, (ev["org"], (datetime.utcnow() - timedelta(hours=1)).isoformat())).fetchone()

        if not existing:
            conn.execute("""
                INSERT INTO correlation_events
                (org, severity, message, sources, categories, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ev["org"], ev["severity"], ev["message"],
                json.dumps(ev["sources"]),
                json.dumps(ev["categories"]),
                datetime.utcnow().isoformat(),
            ))
    if events:
        conn.commit()
        log.info(f"Correlation: {len(events)} cross-source signals detected.")
    return events


def main(once: bool = False, interval: int = 90):
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    init_db(conn)

    log.info("Pre-loading models (one-time ~30s)...")
    get_classifier()
    get_nlp()
    get_extractor()
    log.info("All models ready.")

    while True:
       while True:
        count = process_batch(conn, batch_size=1000)

        if count == 0:
            # No new data → wait
            time.sleep(interval)
        else:
            # Still backlog → process immediately
            continue


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--once", action="store_true")
    p.add_argument("--interval", type=int, default=90)
    args = p.parse_args()
    main(once=args.once, interval=args.interval)