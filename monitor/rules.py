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

    # HIGH: curl piped to any shell
    if binary == "curl" and parsed_cmd["pipe"]:
        return "HIGH", "curl piped to shell (possible remote command execution)"

    # LOW: curl downloading file
    if binary == "curl":
        if "-o" in cmd and "http" in cmd:
            return "LOW", "File downloaded via curl"

    # HIGH: bash reverse shell
    if binary == "bash":
        if "/dev/tcp/" in cmd:
            return "HIGH", "Reverse shell using /dev/tcp"

        if "-i" in cmd:
            return "LOW", "Interactive bash shell spawned"

    # Netcat rules
    if binary == "nc":
        if "-e" in cmd:
            return "HIGH", "Netcat command execution detected"

        if "-l" in cmd:
            return "LOW", "Netcat listening mode"

    return "INFO", "Benign LOLBin usage"
