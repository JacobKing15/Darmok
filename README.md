# Darmok (formerly PromptB4ke)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Darmok** is a CLI privacy firewall for developers, DevOps engineers, and technical users who work with LLMs on real infrastructure data.

It sits between you and any LLM. Darmok intercepts input, detects and redacts recognized structured secrets, sends the clean version to the LLM, and reconstructs the response with real values restored. Nothing sensitive leaves your machine in plaintext.

> **Privacy Guarantee**: Darmok strictly protects recognized structured secrets: API keys, private keys, JWTs, URL-embedded credentials, email addresses, IP addresses, and credit card numbers. It does *not* cover unstructured text like proprietary business logic.

---

## 🚀 Features

- **Hybrid Detection Pipeline**: Uses regex for structured patterns combined with confidence heuristics and context disambiguation.
- **Encrypted Local Vault**: Safely maps local credentials to session IDs using Argon2id for Key Derivation and AES-256-GCM for encryption.
- **Round-Trip Reconstruction**: Re-injects your secure values back into the LLM's response locally using a per-exchange outbound manifest.
- **Configurable Thresholds**: Fine-tune what gets auto-redacted, blocked for review, or logged.

---

## 📦 Installation

To get started, clone the repository and install the required dependencies:

```bash
git clone https://github.com/your-username/darmok.git
cd darmok
pip install -r requirements.txt
```

---

## 🛠️ Usage

### 1. Initialize the Vault
Before using Darmok for redaction, you must initialize the encrypted vault which stores the mappings of your placeholders to real secrets.
```bash
darmok --vault-init
```

### 2. Sanitizing Prompts (CLI Pipeline)
You can pipe text through Darmok to clean it before it reaches external APIs:
```bash
cat prompt.txt | darmok
# Or use input/output flags directly:
darmok --input prompt.txt --output clean.txt
```

### 3. Restoring Responses
When the LLM replies with placeholders (e.g., `[sess_a3f9b2:API_KEY_1]`), you can restore the secure values:
```bash
darmok --restore --session sess_a3f9b2 --input response.txt
```

### 4. Interactive Mode
If a detected secret falls into a specific confidence threshold, Darmok will trigger an interactive review mode to have you explicitly decide whether to redact, skip, or allowlist the pattern.
```bash
darmok --interactive
```

---

## 📚 Library API
Darmok exposes its core functionality as an importable module. You can integrate `darmok.pipeline.Pipeline`, `darmok.vault.Vault`, and `darmok.session.SessionManager` directly into your native Python applications.

```python
from darmok.pipeline import Pipeline

pipeline = Pipeline()
# Run your detection/redaction operations here
```

---

## 🧪 Testing

The library comes with a comprehensive test suite (250+ tests). You can run them simply using `pytest`:
```bash
pytest
```

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).
