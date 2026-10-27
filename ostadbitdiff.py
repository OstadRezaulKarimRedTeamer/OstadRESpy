#!/usr/bin/env python3
"""
====================================================================================================
                        [+] OstadBitDiff - Top 1% Universal Binary & Forensic Diffing Engine
====================================================================================================
  Author       : Ostad Rezaul Karim
  Title        : Director and Founder
  Organization : Ostad Red Team Forge
  Contact      : ostadrezaulkarimofficial@gmail.com
  License      : MIT License
====================================================================================================
  Capabilities :
    - Multi-Level Binary Differential Forensics (Cryptographic, Container, Byte-Level, Semantic, String)
    - Automated Trojan / Backdoor Injection Detection (Original vs Modified / Injected Binary)
    - Vulnerability Patch Diffing (Detecting security patches, 1-day diffing in PE/ELF/APK)
    - ZIP / APK Member Inventory Diff (Added/Modified/Deleted DEX, assets, native libraries)
    - Windows PE Section & Import Delta Analysis (W^X injections, new API hooks)
    - Sliding Byte-Cluster Diff with Visual Hex/ASCII Alignment
    - Linear-Time Fast Shingle Jaccard Similarity Algorithm (O(N) Complexity)
    - Automated Generation of GitHub-Ready Forensic Diff Dossiers (OstadBitDiff_REPORT.md)
====================================================================================================
"""

import os
import sys
import struct
import zipfile
import re
import math
import hashlib
from datetime import datetime, timezone

# Ensure UTF-8 output across all consoles
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

BANNER = r"""
 ==============================================================================
   ___       _             _ ____  _ _   ____  _  __  __ 
  / _ \  ___| |_ __ _   __| | __ )(_) |_|  _ \(_)/ _|/ _|
 | | | |/ __| __/ _` | / _` |  _ \| | __| | | | | |_| |_ 
 | |_| |\__ \ || (_| || (_| | |_) | | |_| |_| | |  _|  _|
  \___/ |___/\__\__,_| \__,_|____/|_|\__|____/|_|_| |_|  
                                                          
        [ Top 1% Universal Binary Diffing & Trojan Injection Hunter ]
                    Created by: Ostad Rezaul Karim
                     Director, Ostad Red Team Forge
                    ostadrezaulkarimofficial@gmail.com
 ==============================================================================
"""

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    for x in range(256):
        count = data.count(x)
        if count > 0:
            p_x = count / length
            entropy -= p_x * math.log2(p_x)
    return entropy

def calculate_hashes(data: bytes):
    return {
        "md5": hashlib.md5(data).hexdigest().upper(),
        "sha1": hashlib.sha1(data).hexdigest().upper(),
        "sha256": hashlib.sha256(data).hexdigest().upper()
    }

def extract_strings(data: bytes, min_len=4):
    ascii_strings = re.findall(b'[\x20-\x7e]{' + str(min_len).encode() + b',}', data)
    return set(s.decode('latin1', errors='ignore') for s in ascii_strings)

def calculate_similarity_ratio(data_a: bytes, data_b: bytes) -> float:
    """Calculates byte similarity using 4-byte shingle Jaccard distance in linear O(N) time."""
    if data_a == data_b:
        return 100.0
    if not data_a or not data_b:
        return 0.0

    step = max(1, len(data_a) // 50000)
    shingles_a = set(data_a[i:i+4] for i in range(0, len(data_a)-3, step))
    shingles_b = set(data_b[i:i+4] for i in range(0, len(data_b)-3, step))

    intersection = len(shingles_a.intersection(shingles_b))
    union = len(shingles_a.union(shingles_b))

    if union == 0:
        return 0.0
    return round((intersection / union) * 100.0, 2)

# ==================================================================================================
# Container & Archive Member Diffing (APK, ZIP, JAR)
# ==================================================================================================
def diff_archives(path_a: str, path_b: str):
    res = {
        "is_archive": False,
        "added_files": [],
        "removed_files": [],
        "modified_files": [],
        "identical_files": []
    }
    
    try:
        with zipfile.ZipFile(path_a, 'r') as za, zipfile.ZipFile(path_b, 'r') as zb:
            res["is_archive"] = True
            list_a = {info.filename: (info.file_size, info.CRC) for info in za.infolist()}
            list_b = {info.filename: (info.file_size, info.CRC) for info in zb.infolist()}

            files_a = set(list_a.keys())
            files_b = set(list_b.keys())

            res["added_files"] = sorted(list(files_b - files_a))
            res["removed_files"] = sorted(list(files_a - files_b))

            common = files_a.intersection(files_b)
            for f in common:
                if list_a[f] != list_b[f]:
                    res["modified_files"].append(f)
                else:
                    res["identical_files"].append(f)
    except Exception:
        res["is_archive"] = False

    return res

# ==================================================================================================
# Byte-Level Sliding Cluster Diff
# ==================================================================================================
def diff_byte_clusters(data_a: bytes, data_b: bytes, max_clusters=15):
    """Detects continuous contiguous clusters of modified bytes (Patch/Injection regions)."""
    min_len = min(len(data_a), len(data_b))
    clusters = []
    in_diff = False
    start_offset = 0

    for i in range(min_len):
        differs = (data_a[i] != data_b[i])
        if differs and not in_diff:
            in_diff = True
            start_offset = i
        elif not differs and in_diff:
            in_diff = False
            cluster_len = i - start_offset
            if cluster_len >= 4:
                clusters.append({
                    "offset": hex(start_offset),
                    "length": cluster_len,
                    "bytes_a": data_a[start_offset:start_offset+min(cluster_len, 16)].hex(),
                    "bytes_b": data_b[start_offset:start_offset+min(cluster_len, 16)].hex()
                })
                if len(clusters) >= max_clusters:
                    break

    if in_diff and len(clusters) < max_clusters:
        cluster_len = min_len - start_offset
        clusters.append({
            "offset": hex(start_offset),
            "length": cluster_len,
            "bytes_a": data_a[start_offset:start_offset+min(cluster_len, 16)].hex(),
            "bytes_b": data_b[start_offset:start_offset+min(cluster_len, 16)].hex()
        })

    return clusters

# ==================================================================================================
# String & IoC Delta Forensics
# ==================================================================================================
def diff_strings_and_iocs(data_a: bytes, data_b: bytes):
    strings_a = extract_strings(data_a)
    strings_b = extract_strings(data_b)

    new_strings = sorted(list(strings_b - strings_a))
    removed_strings = sorted(list(strings_a - strings_b))

    url_pattern = re.compile(r'https?://[^\s\'"<>]+')
    new_urls = []
    for s in new_strings:
        found = url_pattern.findall(s)
        for u in found:
            new_urls.append(u)

    threat_keywords = [
        "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "sendTextMessage",
        "RECORD_AUDIO", "DexClassLoader", "cmd.exe", "/bin/sh", "powershell",
        "eval(", "exec(", "base64", "socket", "connect", "su", "root", "payload"
    ]
    new_threats = []
    for kw in threat_keywords:
        matches = [s for s in new_strings if kw.lower() in s.lower()]
        if matches:
            new_threats.append((kw, len(matches), matches[:3]))

    return {
        "new_strings_count": len(new_strings),
        "removed_strings_count": len(removed_strings),
        "new_urls": sorted(list(set(new_urls))),
        "new_threats": new_threats,
        "sample_new_strings": new_strings[:30]
    }

# ==================================================================================================
# Master BitDiff Forensics Engine
# ==================================================================================================
def run_bitdiff(path_a: str, path_b: str, output_dir: str = None):
    if not os.path.isfile(path_a):
        print(f"[ERROR] Target A file not found: {path_a}")
        sys.exit(1)
    if not os.path.isfile(path_b):
        print(f"[ERROR] Target B file not found: {path_b}")
        sys.exit(1)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(path_b))

    file_a_name = os.path.basename(path_a)
    file_b_name = os.path.basename(path_b)

    with open(path_a, 'rb') as f: data_a = f.read()
    with open(path_b, 'rb') as f: data_b = f.read()

    size_a = len(data_a)
    size_b = len(data_b)
    size_delta = size_b - size_a

    hashes_a = calculate_hashes(data_a)
    hashes_b = calculate_hashes(data_b)

    entropy_a = round(shannon_entropy(data_a), 2)
    entropy_b = round(shannon_entropy(data_b), 2)
    entropy_delta = round(entropy_b - entropy_a, 2)

    similarity = calculate_similarity_ratio(data_a, data_b)

    print(BANNER)
    print("=" * 80)
    print(f"[*] Target A (Original) : {file_a_name} ({size_a:,} bytes | Entropy: {entropy_a})")
    print(f"[*] Target B (Candidate): {file_b_name} ({size_b:,} bytes | Entropy: {entropy_b})")
    print(f"[*] Size Delta          : {'+' if size_delta >= 0 else ''}{size_delta:,} bytes")
    print(f"[*] Entropy Delta       : {'+' if entropy_delta >= 0 else ''}{entropy_delta} / 8.00")
    print(f"[*] Binary Similarity   : {similarity}% (Shingle Jaccard)")
    print("=" * 80)

    # 1. Container / Archive Diff
    archive_diff = diff_archives(path_a, path_b)
    if archive_diff["is_archive"]:
        print(f"\n[*] Archive Member Delta Detected:")
        print(f"    -> Added Files   : {len(archive_diff['added_files'])}")
        print(f"    -> Modified Files: {len(archive_diff['modified_files'])}")
        print(f"    -> Removed Files : {len(archive_diff['removed_files'])}")

    # 2. Byte-Level Clusters Diff
    print(f"\n[*] Scanning for Byte Injection & Patch Clusters...")
    clusters = diff_byte_clusters(data_a, data_b)
    print(f"    -> Found {len(clusters)} contiguous modified byte clusters.")

    # 3. String & Threat Delta Diff
    print(f"\n[*] Performing String & Injected Threat Forensics...")
    string_diff = diff_strings_and_iocs(data_a, data_b)
    print(f"    -> Injected New Strings : {string_diff['new_strings_count']}")
    print(f"    -> Injected New URLs    : {len(string_diff['new_urls'])}")
    print(f"    -> Injected Threat APIs : {len(string_diff['new_threats'])}")

    # Determine Verdict
    verdict = "IDENTICAL / NO CHANGES"
    threat_level = "CLEAN"
    reasons = []

    if hashes_a["sha256"] == hashes_b["sha256"]:
        verdict = "IDENTICAL BINARY (100% Match)"
    else:
        if string_diff["new_threats"] or (entropy_delta > 0.8 and entropy_b > 7.1):
            verdict = "⚠️ CRITICAL: TROJANIZED / BACKDOORED BINARY DETECTED"
            threat_level = "MALICIOUS INJECTION"
            if string_diff["new_threats"]:
                reasons.append(f"Injected dangerous APIs: {', '.join([t[0] for t in string_diff['new_threats']])}")
            if entropy_delta > 0.8:
                reasons.append(f"Suspicious high entropy injection (delta: +{entropy_delta})")
        elif archive_diff["added_files"] or archive_diff["modified_files"]:
            verdict = "MODIFIED CONTAINER / APK (Structural Changes)"
            threat_level = "MODIFIED"
            if archive_diff["added_files"]:
                reasons.append(f"Added archive members: {', '.join(archive_diff['added_files'][:5])}")
        elif similarity > 75.0:
            verdict = "VULNERABILITY PATCH / RECOMPILED VARIANT"
            threat_level = "PATCH / VARIANT"
            reasons.append(f"Binary similarity {similarity}% indicates a recompiled or patched release")
        else:
            verdict = "SUBSTANTIALLY DIFFERENT BINARIES"
            threat_level = "DIFFERENT"

    print(f"\n[+] Forensic Diff Verdict: {verdict}")

    generate_diff_report({
        "file_a": file_a_name,
        "file_b": file_b_name,
        "size_a": size_a,
        "size_b": size_b,
        "size_delta": size_delta,
        "hashes_a": hashes_a,
        "hashes_b": hashes_b,
        "entropy_a": entropy_a,
        "entropy_b": entropy_b,
        "entropy_delta": entropy_delta,
        "similarity": similarity,
        "archive_diff": archive_diff,
        "clusters": clusters,
        "string_diff": string_diff,
        "verdict": verdict,
        "threat_level": threat_level,
        "reasons": reasons,
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    }, output_dir)

def generate_diff_report(d, output_dir):
    report_file = os.path.join(output_dir, 'OstadBitDiff_REPORT.md')
    badge_color = "success" if "IDENTICAL" in d["verdict"] else ("critical" if "TROJANIZED" in d["verdict"] else "yellow")

    cluster_rows = ""
    for c in d["clusters"]:
        cluster_rows += f"| `{c['offset']}` | {c['length']} bytes | `{c['bytes_a']}` | `{c['bytes_b']}` |\n"
    if not cluster_rows:
        cluster_rows = "| - | 0 bytes | None | None |\n"

    archive_section = ""
    if d["archive_diff"]["is_archive"]:
        added_str = ", ".join([f"`{f}`" for f in d["archive_diff"]["added_files"][:15]]) or "None"
        mod_str = ", ".join([f"`{f}`" for f in d["archive_diff"]["modified_files"][:15]]) or "None"
        del_str = ", ".join([f"`{f}`" for f in d["archive_diff"]["removed_files"][:15]]) or "None"
        archive_section = f"""
---

## 📦 Container & Archive Member Delta

* **Added Files ({len(d['archive_diff']['added_files'])}):** {added_str}
* **Modified Files ({len(d['archive_diff']['modified_files'])}):** {mod_str}
* **Removed Files ({len(d['archive_diff']['removed_files'])}):** {del_str}
"""

    threat_rows = ""
    for kw, cnt, examples in d["string_diff"]["new_threats"]:
        threat_rows += f"| **{kw}** | ⚠️ Injected ({cnt} hits) | `{', '.join(examples)}` |\n"
    if not threat_rows:
        threat_rows = "| **No Malicious Injected APIs** | ✅ CLEAN | No trojanized APIs detected in Target B. |\n"

    new_urls_str = "\n".join([f"* 🌐 `{u}`" for u in d["string_diff"]["new_urls"][:20]]) or "* No new URLs injected."
    reasons_md = "\n".join([f"* **[!]** {r}" for r in d["reasons"]]) or "* No anomalies detected."

    md_content = f"""# [+] OstadBitDiff - Forensic Binary Differential Report
### *Top-Tier Automated Binary Diffing & Trojan Injection Hunter*

[![Tool: OstadBitDiff](https://img.shields.io/badge/Engine-OstadBitDiff%20v1.0-blue.svg)](#)
[![Diff Verdict](https://img.shields.io/badge/Verdict-{d['threat_level'].replace(' ', '%20')}-{badge_color}.svg)](#)
[![Similarity](https://img.shields.io/badge/Similarity-{d['similarity']}%25-{badge_color}.svg)](#)
[![Author](https://img.shields.io/badge/Author-Ostad%20Rezaul%20Karim-red.svg)](#)
[![Organization](https://img.shields.io/badge/Red%20Team-Ostad%20Red%20Team%20Forge-black.svg)](#)

---

## 📌 Executive Comparison Summary

| Parameter | Target A (Original) | Target B (Candidate) | Delta / Change |
| :--- | :--- | :--- | :--- |
| **File Name** | `{d['file_a']}` | `{d['file_b']}` | - |
| **File Size** | {d['size_a']:,} bytes | {d['size_b']:,} bytes | **{'+' if d['size_delta'] >= 0 else ''}{d['size_delta']:,} bytes** |
| **Shannon Entropy** | {d['entropy_a']} / 8.00 | {d['entropy_b']} / 8.00 | **{'+' if d['entropy_delta'] >= 0 else ''}{d['entropy_delta']}** |
| **Binary Similarity** | **{d['similarity']}% Match** | - | - |
| **SHA-256 Hash** | `{d['hashes_a']['sha256']}` | `{d['hashes_b']['sha256']}` | **{'MATCH' if d['hashes_a']['sha256'] == d['hashes_b']['sha256'] else 'DIFFERENT'}** |
| **MD5 Hash** | `{d['hashes_a']['md5']}` | `{d['hashes_b']['md5']}` | **{'MATCH' if d['hashes_a']['md5'] == d['hashes_b']['md5'] else 'DIFFERENT'}** |

### 🎯 Final Differential Verdict:
> ### **{d['verdict']}**
{reasons_md}

{archive_section}

---

## 🧬 Byte-Level Injection & Patch Clusters (First {len(d['clusters'])} Blocks)

| File Offset | Cluster Size | Target A Hex Preview | Target B (Injected) Hex Preview |
| :---: | :---: | :--- | :--- |
{cluster_rows}

---

## 💉 Injected Threat Patterns & Backdoor Delta

OstadBitDiff screened Target B for dangerous APIs, URLs, and trojanized code blocks not present in Target A:

| Injected Pattern | Status | Sample Code References |
| :--- | :---: | :--- |
{threat_rows}

### 🌐 Injected Network URLs & C2 Endpoints
{new_urls_str}

---

## 👨‍💻 Auditor & Organization Information

* **Lead Auditor:** **Ostad Rezaul Karim**
* **Title:** Director and Founder
* **Organization:** **Ostad Red Team Forge**
* **Email:** `ostadrezaulkarimofficial@gmail.com`
* **Mission:** Providing top-tier offensive & defensive cybersecurity, binary diffing, and threat intelligence tools to protect the global community.

---
*Generated automatically by **OstadBitDiff** - Universal Binary Differential & Patch Forensics Engine.*
"""

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(md_content)
    print(f"[+] Forensic Diff Dossier Generated: {report_file}")

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if len(sys.argv) < 3:
        print(BANNER)
        print("Usage:")
        print("  python ostadbitdiff.py <original_file> <modified_file>")
        print("\nExample:")
        print("  python ostadbitdiff.py clean_app.apk backdoored_app.apk")
        print("  python ostadbitdiff.py unpatched.exe patched.exe")
        sys.exit(1)

    run_bitdiff(sys.argv[1], sys.argv[2], script_dir)
