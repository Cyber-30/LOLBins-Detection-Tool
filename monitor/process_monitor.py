import psutil
import os
import time
from collections import deque
from monitor.rules import map_mitre, is_lolbin, is_noise, detect_malicious, is_trusted_url
from monitor.command_parser import parse_command

PROCESS_LOG = "logs/process.log"
INFO_LOG = "logs/info.log"
ALERT_LOG = "logs/alerts.log"

BASH_HISTORY = os.path.expanduser("~/.bash_history")

seen_pids = set()
alerted_chains = set()
recent_processes = deque(maxlen=20)
history_offset = 0


def log(file, message):
    with open(file, "a") as f:
        f.write(message + "\n")


def init_shell_history():
    global history_offset
    try:
        with open(BASH_HISTORY, "r") as f:
            history_offset = len(f.readlines())
    except Exception:
        history_offset = 0


def check_shell_history():
    """Detect dangerous shell commands from new bash history entries"""
    global history_offset
    try:
        with open(BASH_HISTORY, "r") as f:
            lines = f.readlines()

        new_lines = lines[history_offset:]
        history_offset = len(lines)

        for line in new_lines:
            line = line.strip()
            if not line:
                continue

            if "|" in line and ("curl" in line or "wget" in line) and ("bash" in line or "sh" in line):
                parsed = parse_command(line)
                # Skip if only trusted URLs
                urls = parsed.get("urls", [])
                if urls and all(is_trusted_url(u) for u in urls):
                    continue

                signals = {"shell-history", "pipe", "downloader", "external_url"}
                mitre = map_mitre(signals)
                log(
                    ALERT_LOG,
                    f"[HIGH] shell-history | remote command execution via pipe | "
                    f"{line} | signals={','.join(signals)} | MITRE={','.join(mitre)}"
                )

    except Exception:
        pass


def detect_process_chain(now, name):
    """Detect temporal chain: curl/wget → bash/sh within 2 seconds"""
    if name not in ("bash", "sh"):
        return False

    for t, pname, pcmd in reversed(recent_processes):
        if now - t > 2:
            break

        if pname in ("curl", "wget"):
            key = f"{pname}->{name}"
            if key not in alerted_chains:
                alerted_chains.add(key)
                return True

    return False


def monitor_processes():
    init_shell_history()

    while True:
        check_shell_history()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cmdline = proc.info['cmdline']

                if not cmdline or pid in seen_pids:
                    continue

                seen_pids.add(pid)
                cmd = " ".join(cmdline)
                now = time.time()

                log(PROCESS_LOG, f"{pid} | {name} | {cmd}")
                recent_processes.append((now, name, cmd))

                # Detect process chain
                if detect_process_chain(now, name):
                    signals = {"temporal_chain", "downloader", "shell"}
                    mitre = map_mitre(signals)
                    log(
                        ALERT_LOG,
                        f"[HIGH] process-chain | downloader followed by shell (possible pipe execution) | "
                        f"{cmd} | signals={','.join(signals)} | MITRE={','.join(mitre)}"
                    )

                # Skip non-LOLBin binaries
                if not is_lolbin(name):
                    continue
                if is_noise(cmd):
                    continue

                # Parse command
                parsed = parse_command(cmd)

                # False-positive filtering: skip trusted URLs
                urls = parsed.get("urls", [])
                if urls and all(is_trusted_url(u) for u in urls):
                    continue

                # Detect malicious behavior
                severity, reason = detect_malicious(name, parsed)

                signals = {name}
                if parsed.get("pipe"):
                    signals.add("pipe")
                if urls:
                    signals.add("external_url")
                if severity != "INFO" and name in ("bash", "sh"):
                    signals.add("shell")

                mitre = map_mitre(signals)

                if severity == "INFO":
                    log(INFO_LOG, f"[INFO] {name} | {parsed}")
                else:
                    log(
                        ALERT_LOG,
                        f"[{severity}] {name} | {reason} | {parsed} | "
                        f"signals={','.join(signals)} | MITRE={','.join(mitre)}"
                    )

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(0.3)


if __name__ == "__main__":
    monitor_processes()
