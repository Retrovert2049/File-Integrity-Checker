import hashlib
import os
import json
from datetime import datetime

BASELINE_FILE = "baseline.json"

def get_file_hash(filepath):
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def add_to_baseline(filepath):
    baseline = {}
    if os.path.exists(BASELINE_FILE):
        with open(BASELINE_FILE, "r") as f:
            baseline = json.load(f)
    
    if not os.path.exists(filepath):
        print(f"[-] File {filepath} does not exist.")
        return

    file_hash = get_file_hash(filepath)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    if filepath in baseline:
        old_hash = baseline[filepath]["hash"]
        old_timestamp = baseline[filepath]["timestamp"]
        if old_hash != file_hash:
            print(f"[MODIFIED] File has changed since last check")
            print(f"Previous hash ({old_timestamp}): {old_hash}")
            print(f"Current hash  ({timestamp}): {file_hash}")
    else:
        print(f"[NEW] Adding new file to baseline")
        print(f"Hash: {file_hash}")
    
    baseline[filepath] = {
        "hash": file_hash,
        "timestamp": timestamp
    }

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)
    print(f"[+] Baseline updated in {BASELINE_FILE}")

def check_file(filepath):
    if not os.path.exists(BASELINE_FILE):
        print("[-] No baseline file found. Add a file first.")
        return

    if not os.path.exists(filepath):
        print(f"[-] File {filepath} does not exist.")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    if filepath not in baseline:
        print(f"[NEW] File {filepath} is not in baseline.")
        return

    current_hash = get_file_hash(filepath)
    stored_hash = baseline[filepath]["hash"]
    stored_timestamp = baseline[filepath]["timestamp"]

    if current_hash == stored_hash:
        print(f"[OK] File integrity verified")
        print(f"Stored hash  ({stored_timestamp}): {stored_hash}")
        print(f"Current hash (now): {current_hash}")
    else:
        print(f"[MODIFIED] File has been modified!")
        print(f"Stored hash  ({stored_timestamp}): {stored_hash}")
        print(f"Current hash (now): {current_hash}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="File Integrity Checker")
    parser.add_argument("command", choices=["add", "check"], help="add file to baseline or check file integrity")
    parser.add_argument("filepath", help="Path to the file")
    args = parser.parse_args()

    if args.command == "add":
        add_to_baseline(args.filepath)
    elif args.command == "check":
        check_file(args.filepath)
