#!/usr/bin/env python3
"""
quicksudo - Secure sudo wrapper for AI agents

Usage:
  - User sets a sudo key: POST /quicksudo/set-key
  - AI executes sudo commands: POST /quicksudo/exec
  - Verify key: POST /quicksudo/verify
"""

import sys
import json
import os
import subprocess
import tempfile
import hashlib
import time
import re
from pathlib import Path

CONFIG_DIR = os.path.expanduser("~/.lian/quicksudo")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
KEY_FILE = os.path.join(CONFIG_DIR, "key.hash")
LOG_FILE = os.path.join(CONFIG_DIR, "audit.log")

def ensure_config_dir():
    os.makedirs(CONFIG_DIR, mode=0o700, exist_ok=True)

def load_config():
    ensure_config_dir()
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {"timeout": 30, "allowed_commands": []}

def save_config(config):
    ensure_config_dir()
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def set_key(key):
    ensure_config_dir()
    with open(KEY_FILE, 'w') as f:
        f.write(hash_key(key))
        f.write(f"\n{time.time()}")
    os.chmod(KEY_FILE, 0o600)
    return True

def verify_key(key):
    if not os.path.exists(KEY_FILE):
        return False
    with open(KEY_FILE) as f:
        stored_hash = f.read().strip().split('\n')[0]
    return hash_key(key) == stored_hash

def is_key_set():
    return os.path.exists(KEY_FILE)

def log_command(command, output, exit_code, duration):
    ensure_config_dir()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, 'a') as f:
        f.write(f"[{timestamp}] Command: {command}\n")
        f.write(f"  Exit code: {exit_code}\n")
        f.write(f"  Duration: {duration:.2f}s\n")
        if exit_code != 0:
            f.write(f"  Output: {output[:500]}\n")
        f.write("\n")

def sanitize_command(command):
    """Remove any sudo/privilege escalation from command"""
    dangerous = ['sudo', 'su ', 'pkexec', 'chmod +s', 'chown root']
    for d in dangerous:
        if d.lower() in command.lower():
            return None
    return command

def execute_command(command, sudo_key):
    config = load_config()
    timeout = config.get('timeout', 30)
    allowed = config.get('allowed_commands', [])

    if not sudo_key or not verify_key(sudo_key):
        return {
            "status": 401,
            "body": {"error": "Invalid or missing sudo key"}
        }

    safe_cmd = sanitize_command(command)
    if safe_cmd is None:
        return {
            "status": 403,
            "body": {"error": "Command contains privilege escalation attempt"}
        }

    if allowed and not any(re.match(pattern, safe_cmd) for pattern in allowed):
        return {
            "status": 403,
            "body": {"error": "Command not in allowed list", "allowed": allowed}
        }

    # Use sudo with the key
    cmd = f"echo '{sudo_key}' | sudo -S {safe_cmd}"
    start = time.time()

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        duration = time.time() - start
        log_command(command, result.stdout + result.stderr, result.returncode, duration)

        return {
            "status": 200 if result.returncode == 0 else 500,
            "body": {
                "success": result.returncode == 0,
                "exit_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "duration_seconds": round(duration, 3)
            }
        }
    except subprocess.TimeoutExpired:
        return {
            "status": 408,
            "body": {"error": f"Command timed out after {timeout} seconds"}
        }
    except Exception as e:
        return {
            "status": 500,
            "body": {"error": str(e)}
        }

def handle_request(data):
    api = data.get('api', '')
    method = data.get('method', '')
    body = data.get('body', {})

    if api == '/quicksudo/set-key' or (api == '/quicksudo/exec' and body.get('action') == 'set_key'):
        key = body.get('key', '')
        if len(key) < 8:
            return {"status": 400, "body": {"error": "Key must be at least 8 characters"}}
        set_key(key)
        return {"status": 200, "body": {"success": True, "message": "Sudo key updated successfully"}}

    if api == '/quicksudo/verify':
        key = body.get('key', '')
        if not key:
            return {"status": 400, "body": {"error": "Key required"}}
        if verify_key(key):
            return {"status": 200, "body": {"valid": True}}
        return {"status": 200, "body": {"valid": False}}

    if api == '/quicksudo/exec':
        command = body.get('command', '')
        sudo_key = body.get('sudo_key', os.environ.get('LIAN_SUDO_KEY', ''))
        if not command:
            return {"status": 400, "body": {"error": "Command required"}}
        return execute_command(command, sudo_key)

    if api == '/quicksudo/config' and method == 'GET':
        config = load_config()
        return {
            "status": 200,
            "body": {
                "key_set": is_key_set(),
                "timeout": config.get('timeout', 30),
                "allowed_commands": config.get('allowed_commands', []),
                "log_file": LOG_FILE if os.path.exists(LOG_FILE) else None
            }
        }

    if api == '/quicksudo/config' and method == 'PUT':
        config = load_config()
        if 'timeout' in body:
            config['timeout'] = int(body['timeout'])
        if 'allowed_commands' in body:
            config['allowed_commands'] = body['allowed_commands']
        save_config(config)
        return {"status": 200, "body": {"success": True, "config": config}}

    return {"status": 404, "body": {"error": "Unknown API endpoint"}}

if __name__ == "__main__":
    try:
        data = json.load(sys.stdin)
        result = handle_request(data)
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"status": 500, "body": {"error": str(e)}}))