import psutil
import os
import time
from monitor.command_parser import parse_command
from monitor.rules import is_lolbin, is_noise, detect_malicious

PROCESS_LOG = "logs/process.log"
INFO_LOG = "logs/info.log"
ALERT_LOG = "logs/alerts.log"

BASH_HISTORY = os.path.expanduser("~/.bash_history")

seen_pids = set()
seen_history = set()

def log(file, message):
    with open(file, "a") as f:
        f.write(message + "\n")

def check_shell_history():
    try:
        with open(BASH_HISTORY, "r") as f:
            lines = f.readlines()[-20:]

        for line in lines:
            line = line.strip()

            if not line or line in seen_history:
                continue

            if "|" in line:
                if ("curl" in line or "wget" in line) and ("bash" in line or "sh" in line):
                    log(
                        ALERT_LOG,
                        f"[HIGH] shell | remote command execution via pipe | {line}"
                    )
                    seen_history.add(line)

    except Exception:
        pass


def monitor_processes():
    while True:
        check_shell_history()

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cmdline = proc.info['cmdline']

                if not cmdline:
                    continue

                if pid in seen_pids:
                    continue

                seen_pids.add(pid)

                cmd = " ".join(cmdline)

                log(PROCESS_LOG, f"{pid} | {name} | {cmd}")

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
