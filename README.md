# CTI Agent IOC Extractor

A professional-grade Cyber Threat Intelligence (CTI) tool for extracting Indicators of Compromise (IOCs) from unstructured reports, articles, and blog posts.

## 🚀 Features

- **Standard IOC Extraction**: Automatically identifies and extracts common indicators using optimized regex patterns:
  - IPv4 Addresses (Plain & Defanged)
  - Domains & URLs (Plain & Defanged)
  - File Hashes (MD5, SHA1, SHA256)
  - CVE IDs & MITRE ATT&CK Techniques (TTPs)
  - Bitcoin Wallets, Emails, Registry Keys, and Named Mutexes.
- **Intelligent Entity Recognition**: Leverages **spaCy NLP** to identify threat actors and malware families that aren't in predefined lists.
- **Advanced Categorization**:
  - **Known**: Matches identified against a curated list of high-profile threat groups and malware.
  - **Unknown**: Potential new threats discovered using Named Entity Recognition (NER) and linguistic context.
- **Context-Aware Discovery**: High-confidence detection for unknown entities by analyzing their proximity to CTI keywords (e.g., "backdoor", "zero-day", "espionage").
- **Structured Output**: Saves all findings into a clean, hierarchical `output.json` file for easy integration with other tools or SIEMs.

## 🛠️ Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/Waseem-javed/Iocs-extractor.git
   cd Iocs-extractor
   ```

2. **Set up a virtual environment**:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install spacy
   python -m spacy download en_core_web_sm
   ```

## 📖 Usage

1. Place your unstructured text report in `app/report.txt`.
2. Run the extractor:
   ```bash
   python3 -m app.app
   ```
3. View the results in `app/output.json`.

## 📂 Project Structure

- `app/app.py`: Core logic for extraction and NLP processing.
- `app/patterns.py`: Curated regex patterns and CTI keyword lists.
- `app/helpers.py`: Utility functions for normalization and classification.
- `app/report.txt`: Input file for unstructured reports.
- `app/output.json`: Structured extraction results.

## 🛡️ Requirements

- Python 3.8+
- spaCy (`en_core_web_sm` model)

---

_Developed for Cyber Threat Intelligence professionals to automate the tedious task of manual IOC collection._
