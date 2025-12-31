import re
from urllib.parse import urlparse

def extract_urls(cmd):
    return re.findall(r"(https?://[^\s]+)", cmd)

def has_pipe(cmd):
    return '|' in cmd

def has_redirected(cmd):
    return '>' in cmd or '<' in cmd

def parse_command(cmd):
    return {
        "raw" : cmd,
        "urls" : extract_urls(cmd),
        "pipe" : has_pipe(cmd),
        "redirected" : has_redirected(cmd) 
    }

def is_shell_pipe(cmd):
    return '|' in cmd

