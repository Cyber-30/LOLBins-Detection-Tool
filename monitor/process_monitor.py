import psutil
import time

LOG_FILE = "logs/process.log"

def log_process(name,pid,cmd):
    with open (LOG_FILE,"a") as f:
        f.write(f"{pid} | {name} | {cmd}\n")


def monitor_processes():
    seen = set()

    while True:
        for process in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                pid = process.info['pid']
                name = process.info['name']
                cmdline = ' '.join(process.info['cmdline'])

                if pid not in seen:
                    seen.add(pid)
                    log_process(name, pid, cmdline)

            except ():
                pass

        time.sleep(2)