# CTI Agent IOC Extractor

A Cyber Threat Intelligence (CTI) tool for extracting Indicators of Compromise (IOCs) and threat context from unstructured reports, articles, and blog posts. It combines regex parsing, spaCy NER, and LLM analysis (via LangChain + OpenRouter).

## Features

- **IOC extraction** — regex-based detection for:
  - IPv4 addresses (plain and defanged)
  - Domains and URLs (plain and defanged)
  - File hashes (MD5, SHA1, SHA256)
  - CVE IDs and MITRE ATT&CK technique IDs (TTPs)
  - Email addresses, registry keys, named mutexes, and user agents
  - Bitcoin wallets (with checksum validation to reduce false positives)
- **Threat actor & malware detection**:
  - **Known** — curated pattern lists in `patterns.py`
  - **spaCy NER** — context-aware unknown entities near CTI keywords
  - **LLM** — LangChain chains for actors, malware, and a short report summary
- **Structured output** — hierarchical `app/output.json` for SIEM or downstream tooling

## Project structure

```
CTI/
├── .env.example          # Environment template (copy to .env)
├── requirements.txt
├── app/
│   ├── app.py            # Main pipeline and CLI entry point
│   ├── patterns.py       # Regex patterns, IOC map, label sets
│   ├── helpers.py        # Normalization, extraction, validation helpers
│   ├── config.py         # Loads settings from .env
│   ├── prompts.py        # LangChain prompt templates
│   ├── chains.py         # LLM client and analysis chains
│   ├── report.txt        # Input report (your text goes here)
│   └── output.json       # Generated results
```

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/Waseem-javed/Iocs-extractor.git
   cd Iocs-extractor
   ```

2. **Create and activate a virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   python -m spacy download en_core_web_sm
   ```

4. **Configure environment variables**

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set your API key and model settings:

   | Variable          | Description                                      |
   | ----------------- | ------------------------------------------------ |
   | `OPENAI_API_KEY`  | API key (e.g. OpenRouter)                          |
   | `OPENAI_API_BASE` | API base URL (default: OpenRouter)                 |
   | `MODEL_NAME`      | Model ID for ChatOpenAI                            |
   | `TEMPERATURE`     | Sampling temperature (default: `0.2`)              |
   | `MAX_TOKENS`      | Max tokens (reserved for future use)             |

   `.env` is gitignored — never commit real credentials.

## Usage

1. Place your report text in `app/report.txt`.
2. Run the extractor:

   ```bash
   python3 -m app.app
   ```

3. Open `app/output.json` for results.

Example output sections:

- `summary` — LLM-generated report summary
- `ips`, `domains`, `urls`, `hashes`, `cves`, `ttps`, etc.
- `threat_actors` / `malware` — each with `known`, `spacy_detected`, `llm_detected`, and `final` lists

## Requirements

- Python 3.10+
- [spaCy](https://spacy.io/) with `en_core_web_sm`
- [LangChain](https://python.langchain.com/) (`langchain-openai`, `langchain-core`)
- [python-dotenv](https://github.com/theskumar/python-dotenv)
- An OpenAI-compatible API key (tested with [OpenRouter](https://openrouter.ai/))

---

_Developed for Cyber Threat Intelligence professionals to automate manual IOC collection and triage._
