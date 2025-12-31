import psutil
import os
import time
from monitor.command_parser import parse_command
from monitor.rules import is_lolbin, is_noise, detect_malicious

PROCESS_LOG = "logs/process.log"
INFO_LOG = "logs/info.log"
ALERT_LOG = "logs/alerts.log"

BASH_HISTORY = os.path.expanduser("~/.bash_history")

def log(file, message):
    with open(file, "a") as f:
        f.write(message + "\n")

def check_shell_history():
    try:
        with open(BASH_HISTORY, "r") as f:
            lines = f.readlines()[-5:]

        for line in lines:
            if "curl" in line and "|" in line and "bash" in line:
                log(ALERT_LOG, f"[HIGH] shell | curl piped to bash | {line.strip()}")

    except:
        pass


def monitor_processes():
    seen_pids = set()

    while True:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cmdline_list = proc.info['cmdline']

                if not cmdline_list:
                    continue

                cmd = " ".join(cmdline_list)

                if pid in seen_pids:
                    continue

                seen_pids.add(pid)

                log(PROCESS_LOG, f"{pid} | {name} | {cmd}")

                if is_lolbin(name):
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
