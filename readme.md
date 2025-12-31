# 🛡️ LOLBins Detection Tool (Linux)

A **behavior-based detection tool** that identifies malicious abuse of **Living-Off-The-Land Binaries (LOLBins)** such as `curl`, `wget`, `bash`, and `sh` on Linux systems.

This project focuses on **real attacker behavior**, not signatures, combining:
- Process monitoring
- Shell history analysis
- Temporal process correlation
- MITRE ATT&CK mapping
- False-positive reduction

---

## 🧠 What are LOLBins?

**Living-Off-The-Land Binaries (LOLBins)** are legitimate system tools that attackers abuse to:
- Download payloads
- Execute remote code
- Evade detection

Examples:
```bash
curl | bash
wget -O- | sh
