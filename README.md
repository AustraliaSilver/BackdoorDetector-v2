<h1 align="center">BackdoorDetector-v2</h1>
<h2 align="center">Open-source tools to scan your minecraft plugins.</h2>
  
## 🛡️ BackdoorDetector-v2 Overview 

BackdoorDetector is a professional tool designed to analyze the source code of Minecraft plugins (.jar files) in order to detect backdoors, malware, and hidden malicious behaviors within plugins before installing them on the server. The system leverages advanced AI (Gemini), the VineFlower/Krakatau decompiler, and a multi-threaded scanning mechanism to ensure maximum speed and accuracy.

## ✨ Key Features
🔍 1. Backdoor Scanning with AI (Gemini)
- Supports Gemini API keys → Enhances AI detection accuracy

🧠 2. In‑Depth Code Analysis
- Fully decompiles plugins using VineFlower -> Faster.
- Proactively decompile using Krakatau when errors occur.

🛡️ 3. Multi‑Layer Static Analysis (Multi‑layer SAST)
Covers multiple levels of inspection:
- Data‑flow analysis.
- Bytecode analysis.
- Symbolic analysis.
- YAML file analysis.
This layered approach helps the tool easily detect deeply hidden backdoors within the code.

⚡ 3. High‑Speed Queue & Multi‑Threaded Scanning
- Every plugin is copied into a temporary directory and decompiled separately → prevents file conflicts.
- Intelligent queue system runs on dedicated threads.
- Automatically re‑scans if an error (ERROR) occurs.

📦 4. SHA‑256 Cache System
- Plugins that have already been scanned will not be scanned again → saves time

## 💻 Usage Examples
- After downloading the .jar file, open Command Prompt and enter:
``` bash
java -jar "Path\to\BackdoorDetector-v2.jar" scan "Path\to\plugin-to-scan.jar" <scan_mode (recommended: AI_MODERN)>
```
⚠️ Note:
- On the first run, a config.properties file will be generated in the execution directory.
- Once it appears, open the file and enter your Gemini API key.
  
## ⚠️ IMPORTANT DISCLAIMER
- This tool is a Static Application Security Testing (SAST) analyzer. It is designed to detect common threats but CANNOT GUARANTEE detection of 100% of all types of backdoors.
- This tool is provided "AS IS", WITHOUT WARRANTY. Users assume all risks associated with its use.

## 👥 Join Our Community

Have questions? Found a bug? Want to contribute? **[Join our Discord!](https://discord.gg/aWP5KuCgPU)**
