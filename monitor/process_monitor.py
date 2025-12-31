import psutil
import os
import time
from collections import deque

from monitor.command_parser import parse_command
from monitor.rules import is_lolbin, is_noise, detect_malicious

PROCESS_LOG = "logs/process.log"
INFO_LOG = "logs/info.log"
ALERT_LOG = "logs/alerts.log"

BASH_HISTORY = os.path.expanduser("~/.bash_history")

seen_pids = set()
seen_history = set()

# Store recent processes for temporal correlation
recent_processes = deque(maxlen=100)

def log(file, message):
    with open(file, "a") as f:
        f.write(message + "\n")

def check_shell_history():
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
                log(
                    ALERT_LOG,
                    f"[HIGH] shell-history | remote command execution via pipe | {line}"
                )

    except Exception:
        pass


def monitor_processes():
    while True:
        # Best-effort shell telemetry
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

                # Track recent process execution
                recent_processes.append((now, name, cmd))

                # Temporal correlation: curl -> bash within 1 second
                if name in ("bash", "sh"):
                    for t, pname, pcmd in recent_processes:
                        if pname in ("curl", "wget") and now - t < 1:
                            log(
                                ALERT_LOG,
                                "[HIGH] process-chain | downloader followed by shell (possible pipe execution) | curl/wget -> shell"
                            )
                            break

                # LOLBins logic
                if not is_lolbin(name):
                    continue

                if is_noise(cmd):
                    continue

                parsed = parse_command(cmd)
                severity, reason = detect_malicious(name, parsed)

                if severity == "INFO":
                    log(INFO_LOG, f"[INFO] {name} | {parsed}")
                else:
                    log(ALERT_LOG, f"[{severity}] {name} | {reason} | {parsed}")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        time.sleep(0.3)

if __name__ == "__main__":
    monitor_processes()
