# 🛡️ BackdoorDetector-v2 (v1.1.1)

**BackdoorDetector-v2** is a professional Static Application Security Testing (SAST) analyzer designed to scan Minecraft plugins (`.jar` files) for backdoors, malware, and suspicious hidden behaviors before installing them on your server.

This system leverages multi-layered static analysis at the client level, combined with secure, encrypted communication (Hybrid Encryption) to a private Node.js AI Backend that performs advanced LLM validation and serves a real-time monitoring Web Dashboard.

---

## ✨ Features

### 1. Multi-Layered Static Analysis (Client-side)
The local Java scanner runs several high-speed analysis pipelines:
* **Bytecode Analysis (ASM9):** Inspects compiled `.class` files for dangerous APIs (`Runtime.exec`, `ProcessBuilder`, custom `ClassLoader`, reflection), calculates Shannon Entropy of string constants to discover obfuscation, and extracts IP/Domain names.
* **Taint Flow Analysis (Abstract Interpretation):** Tracks untrusted user input (e.g. Chat/Command events) flowing to critical sinks (e.g. OP grant, console command execution, shell spawn) without proper validation/sanitization.
* **Obfuscation & AST Analyzer (JavaParser):** Evaluates cyclomatic complexity, meaningless identifier names (a, b, c), and XOR loops typically used for class/string decryption.
* **Signature Detection:** Rapidly inspects the JAR structure using `LMXBackdoorDetector` to instantly identify signatures of known malware families like L.M.X and OpenEctasy.

### 2. Private AI Backend & Real-time Web Dashboard
A private backend serves as a secure gateway for LLM evaluation and dashboard visualization:
* **Hybrid Encryption:** Payloads sent via HTTP are encrypted using a temporary AES-256-GCM key, which is itself encrypted using the server's RSA-4096 public key.
* **Replay Attack Protection:** Verifies timestamp headers with a max clock skew (5 mins) to prevent attackers from replaying clean scanning payloads.
* **Proof of Work (PoW) DDoS Prevention:** Clients solve a SHA-256 challenge before submitting scans. Difficulty automatically adjusts dynamically under traffic load to throttle spam.
* **Multi-tiered Rate Limiting:**
  * IP-based rate limiting (30 requests/min).
  * Per-client AI rate limiting (10 queries/min) to safeguard API key quotas.
  * Server-wide global rate limiting (**1 request/sec**) to prevent CPU resource exhaustion.
* **Web Dashboard:** A gorgeous dark-themed dashboard styled with CSS Glassmorphism showing:
  * Total requests, total bytes processed, unique plugins scanned.
  * Safe vs Malicious ratio chart.
  * Real-time table feed (refreshing every 8s) showing the last 10 scans with risk scores, verdicts, and indicators.

---

## 🛠️ System Architecture

```
D:\BackdoorDetector-v2
 ┣ 📂 src/main/java/backdoordetected     # Client-side Java SAST analyzer
 ┣ 📂 ai-backend                         # Private Node.js AI Backend & Dashboard (Not Open-Source)
 ┃ ┣ 📂 public                           # Web Dashboard UI files
 ┃ ┣ 📂 src                              # AI caller and caching mechanisms
 ┃ ┗ 📜 index.js                         # Express server, Cryptography, PoW, Rate Limiting
 ┣ 📜 config.properties                  # Client-side settings (minimal config, no backend URL leak)
 ┗ 📜 pom.xml                            # Maven project configuration
```

---

## 🚀 How to Use

### 1. Building the Scanner (Client-side)
Ensure Maven is installed and compile the project:
```bash
mvn clean package -DskipTests=true
```
The compiled executable fat-jar will be generated at `target/BackdoorDetect-1.1.1.jar`.

### 2. Scanning a Plugin
Run the scan command:
```bash
java -jar target/BackdoorDetect-1.1.1.jar scan "path/to/plugin.jar" AI_MODERN
```
* **AI_MODERN:** The default recommended mode. Performs local static analysis, decrypts the PoW challenge, encrypts the findings, and queries the private backend for LLM verification.
* By default, the client is pre-configured to communicate directly with your private backend server (`http://93.115.101.157:13384`).

---

## ⚠️ Disclaimer
* This tool is a Static Application Security Testing (SAST) analyzer. While it offers high accuracy, it **CANNOT GUARANTEE** 100% detection of all backdoor types.
* This tool is provided "AS IS", WITHOUT WARRANTY. Users assume all risks associated with its use.

## 👥 Join Our Community

* Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/aWP5KuCgPU)**

