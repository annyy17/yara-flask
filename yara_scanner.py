import yara
import os

def scan_file(rule_path, file_path):
    rules = yara.compile(filepath=rule_path)
    matches = rules.match(file_path)
    
    if matches:
        print(f"⚠ Malware detected in: {file_path}")
        print(f"Matched Rules: {matches}")
    else:
        print(f"✅ No threats found in: {file_path}")

# Example Usage
scan_file("trojan_rule.yar", "sample_malware.exe")

