import json

with open("config/lolbins.json") as f:
    LOLBINS = json.load(f)

IGNORED_KEYWORDS = [
    "vscode",
    "shellIntegration",
    "cpuUsage.sh",
    "/usr/share/code/",
    "--init-file"
]


def is_lolbin(binary):
    return binary in LOLBINS


def is_noise(cmd):
    for keyword in IGNORED_KEYWORDS:
        if keyword in cmd:
            return True
    return False


def detect_malicious(binary, parsed_cmd):
    cmd = parsed_cmd["raw"]

    # curl rules
    if binary == "curl":
        if "-o" in cmd or "-O" in cmd:
            return "LOW", "File downloaded via curl"

        return "INFO", "curl execution observed"

    # bash rules
    if binary == "bash":
        if "/dev/tcp/" in cmd:
            return "HIGH", "Reverse shell using /dev/tcp"

        return "INFO", "bash execution observed"

    # netcat rules
    if binary == "nc":
        if "-e" in cmd:
            return "HIGH", "Netcat remote command execution"

        if "-l" in cmd:
            return "LOW", "Netcat listening mode"

    return "INFO", "Benign LOLBin usage"


# ---------------- MITRE ATT&CK ---------------- #

MITRE_MAPPING = {
    "downloader": {
        "technique": "T1105",
        "name": "Ingress Tool Transfer"
    },
    "shell": {
        "technique": "T1059",
        "name": "Command and Scripting Interpreter"
    },
    "pipe": {
        "technique": "T1059.004",
        "name": "Unix Shell"
    },
    "temporal_chain": {
        "technique": "T1059",
        "name": "Command Execution"
    },
    "external_url": {
        "technique": "T1105",
        "name": "Ingress Tool Transfer"
    }
}


def map_mitre(signals):
    techniques = []

    for sig in signals:
        if sig in MITRE_MAPPING:
            techniques.append(
                f"{MITRE_MAPPING[sig]['technique']} ({MITRE_MAPPING[sig]['name']})"
            )

    return list(set(techniques))


# ---------------- FALSE POSITIVE REDUCTION ---------------- #

TRUSTED_DOMAINS = (
    "localhost",
    "127.0.0.1",
    "example.com",
    "google.com"
)


def is_trusted_url(url):
    return any(domain in url for domain in TRUSTED_DOMAINS)
