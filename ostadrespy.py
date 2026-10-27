#!/usr/bin/env python3
"""
====================================================================================================
                        🛡️ OstadRESpy - Universal Reverse Engineering & Threat Analyzer
                                 [All-in-One 10-Layer Defense Engine Edition]
====================================================================================================
  Author       : Ostad Rezaul Karim
  Title        : Director and Founder
  Organization : Ostad Red Team Forge
  Contact      : ostadrezaulkarimofficial@gmail.com
  License      : MIT License
====================================================================================================
  10 Integrated Defense Engines:
    1. Built-in YARA APT & Ransomware Signature Engine
    2. OWASP Mobile Top 10 Automated Vulnerability Auditor
    3. Embedded Firmware & RootFS Carver (Binwalk-like)
    4. Memory Forensics & Shellcode Prologue Hunter
    5. Network Forensics, DGA & DNS Tunneling Analyzer
    6. Dynamic Sandbox Behavior & Runtime Simulator
    7. Dynamic Binary Instrumentation (DBI) & Auto-Frida Hook Generator
    8. Symbolic Execution & Time-Bomb Branch Constraint Solver
    9. Air-Gapped Disposable Isolation Chamber
   10. Interactive Bytecode & Opcode Sled Disassembler
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

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Import the 10 Specialized Defense Engines
try:
    from engines.engine_yara import scan_yara
    from engines.engine_mobile import audit_owasp_mobile
    from engines.engine_firmware import scan_firmware
    from engines.engine_memory import scan_memory_dump
    from engines.engine_network import analyze_network_traffic
    from engines.engine_dynamic import simulate_sandbox_trace
    from engines.engine_dbi import generate_frida_bypass_script, audit_anti_hooking
    from engines.engine_symbolic import analyze_conditional_branches
    from engines.engine_isolation import IsolatedExecutionChamber
    from engines.engine_disasm import scan_opcodes_heuristics
except ImportError:
    # If running directly from within directory
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from engines.engine_yara import scan_yara
    from engines.engine_mobile import audit_owasp_mobile
    from engines.engine_firmware import scan_firmware
    from engines.engine_memory import scan_memory_dump
    from engines.engine_network import analyze_network_traffic
    from engines.engine_dynamic import simulate_sandbox_trace
    from engines.engine_dbi import generate_frida_bypass_script, audit_anti_hooking
    from engines.engine_symbolic import analyze_conditional_branches
    from engines.engine_isolation import IsolatedExecutionChamber
    from engines.engine_disasm import scan_opcodes_heuristics

BANNER = r"""
 ==============================================================================
   ___       _             _ ____  _____ ____             
  / _ \  ___| |_ __ _   __| |  _ \| ____/ ___| _ __  _   _ 
 | | | |/ __| __/ _` | / _` | |_) |  _| \___ \| '_ \| | | |
 | |_| |\__ \ || (_| || (_| |  _ <| |___ ___) | |_) | |_| |
  \___/ |___/\__\__,_| \__,_|_| \_\_____|____/| .__/ \__, |
                                              |_|    |___/ 
      [ All-in-One 10-Layer Defense Engine - Ultimate Cybersecurity Suite ]
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
        "sha256": hashlib.sha256(data).hexdigest().upper(),
        "ssdeep_entropy": round(shannon_entropy(data), 2)
    }

def detect_file_format(data: bytes, filename: str):
    ext = os.path.splitext(filename)[1].lower()
    magic = data[:16]
    
    if magic.startswith(b'PK\x03\x04'):
        if ext in ['.apk', '.xapk', '.apks'] or 'AndroidManifest.xml' in filename:
            return "APK"
        return "ZIP_ARCHIVE"
    elif magic.startswith(b'dex\n'):
        return "DEX"
    elif magic.startswith(b'MZ'):
        return "WINDOWS_PE"
    elif magic.startswith(b'\x7fELF'):
        return "LINUX_ELF"
    elif magic.startswith((b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf', b'\xce\xfa\xed\xfe', b'\xcf\xfa\xed\xfe')):
        return "MACOS_MACHO"
    elif magic.startswith(b'%PDF'):
        return "PDF_DOCUMENT"
    elif magic.startswith(b'{\\rtf'):
        return "RTF_DOCUMENT"
    elif ext in ['.py', '.pyw']:
        return "PYTHON_SCRIPT"
    elif ext in ['.ps1', '.psm1']:
        return "POWERSHELL_SCRIPT"
    elif ext in ['.sh', '.bash']:
        return "SHELL_SCRIPT"
    elif ext in ['.bat', '.cmd']:
        return "BATCH_SCRIPT"
    elif ext in ['.js', '.mjs']:
        return "JAVASCRIPT"
    else:
        return "GENERIC_BINARY"

def decode_axml(data: bytes) -> str:
    if len(data) < 8:
        return "<invalid-axml />"
    header_type, _, _ = struct.unpack('<HHI', data[:8])
    if header_type != 0x0003:
        return "<error>Not an AXML file</error>"

    offset = 8
    strings = []
    xml_output = []
    indent = 0

    while offset < len(data):
        chunk_type, _, chunk_size = struct.unpack('<HHI', data[offset:offset+8])
        chunk_data = data[offset:offset+chunk_size]

        if chunk_type == 0x0001:  # String Pool
            str_cnt, _, flags, str_start, _ = struct.unpack('<IIIII', chunk_data[8:28])
            is_utf8 = bool(flags & (1 << 8))
            offsets = [struct.unpack('<I', chunk_data[28 + 4*i : 32 + 4*i])[0] for i in range(str_cnt)]
            str_pool = chunk_data[str_start:]
            strings = []
            for off in offsets:
                p = off
                if is_utf8:
                    if str_pool[p] & 0x80: p += 2
                    else: p += 1
                    if str_pool[p] & 0x80:
                        length = ((str_pool[p] & 0x7f) << 8) | str_pool[p+1]
                        p += 2
                    else:
                        length = str_pool[p]
                        p += 1
                    s = str_pool[p:p+length].decode('utf-8', errors='replace')
                else:
                    length = struct.unpack('<H', str_pool[p:p+2])[0]
                    p += 2
                    s = str_pool[p:p+length*2].decode('utf-16le', errors='replace')
                strings.append(s)

        elif chunk_type == 0x0102:  # Start Element
            line_num, comment_idx, ns_idx, name_idx, attr_start, attr_size, attr_cnt, id_idx, class_idx, style_idx = struct.unpack('<IIiiHHHHHH', chunk_data[8:36])
            tag_name = strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
            attrs = []
            attr_off = 36
            for _ in range(attr_cnt):
                _, a_name_idx, val_idx, a_type, a_data = struct.unpack('<iiIIi', chunk_data[attr_off:attr_off+20])
                attr_off += 20
                attr_name = strings[a_name_idx] if 0 <= a_name_idx < len(strings) else ""
                if val_idx != 0xFFFFFFFF and val_idx < len(strings):
                    val = strings[val_idx]
                else:
                    dtype = a_type >> 24
                    if dtype == 0x12: val = "true" if a_data != 0 else "false"
                    elif dtype == 0x10: val = str(a_data)
                    elif dtype == 0x11: val = hex(a_data)
                    elif dtype == 0x01: val = f"@0x{a_data:08x}"
                    else: val = str(a_data)
                attrs.append(f'{attr_name}="{val}"')
            attr_str = (" " + " ".join(attrs)) if attrs else ""
            xml_output.append("  " * indent + f"<{tag_name}{attr_str}>")
            indent += 1

        elif chunk_type == 0x0103:  # End Element
            _, _, _, name_idx = struct.unpack('<IIii', chunk_data[8:24])
            tag_name = strings[name_idx] if 0 <= name_idx < len(strings) else "unknown"
            indent = max(0, indent - 1)
            xml_output.append("  " * indent + f"</{tag_name}>")

        offset += chunk_size

    return "\n".join(xml_output)

def parse_dex_file(dex_bytes: bytes):
    if len(dex_bytes) < 112:
        return {"string_count": 0, "class_count": 0, "method_count": 0, "strings": [], "classes": []}

    string_ids_size = struct.unpack('<I', dex_bytes[56:60])[0]
    string_ids_off = struct.unpack('<I', dex_bytes[60:64])[0]
    type_ids_size = struct.unpack('<I', dex_bytes[64:68])[0]
    type_ids_off = struct.unpack('<I', dex_bytes[68:72])[0]
    method_ids_size = struct.unpack('<I', dex_bytes[88:92])[0]
    class_defs_size = struct.unpack('<I', dex_bytes[96:100])[0]
    class_defs_off = struct.unpack('<I', dex_bytes[100:104])[0]

    strings = []
    for i in range(string_ids_size):
        str_off = struct.unpack('<I', dex_bytes[string_ids_off + 4*i : string_ids_off + 4*i + 4])[0]
        p = str_off
        length, shift = 0, 0
        while True:
            b = dex_bytes[p]
            p += 1
            length |= (b & 0x7f) << shift
            shift += 7
            if not (b & 0x80): break
        null_pos = dex_bytes.find(b'\x00', p)
        if null_pos != -1:
            try: s = dex_bytes[p:null_pos].decode('utf-8')
            except: s = dex_bytes[p:null_pos].decode('latin1', errors='replace')
            strings.append(s)
        else: strings.append("")

    types = []
    for i in range(type_ids_size):
        desc_idx = struct.unpack('<I', dex_bytes[type_ids_off + 4*i : type_ids_off + 4*i + 4])[0]
        types.append(strings[desc_idx] if desc_idx < len(strings) else f"Type_{desc_idx}")

    classes = []
    for i in range(class_defs_size):
        c_idx = struct.unpack('<I', dex_bytes[class_defs_off + 32*i : class_defs_off + 32*i + 4])[0]
        classes.append(types[c_idx] if c_idx < len(types) else f"Class_{c_idx}")

    return {
        "string_count": string_ids_size,
        "class_count": class_defs_size,
        "method_count": method_ids_size,
        "strings": strings,
        "classes": classes
    }

def verify_apk_signatures(apk_bytes: bytes):
    eocd_pos = apk_bytes.rfind(b'\x50\x4b\x05\x06')
    if eocd_pos == -1:
        return {"v2": False, "v3": False, "play_stamp": False, "certs": []}

    cd_size, cd_off = struct.unpack('<II', apk_bytes[eocd_pos+12:eocd_pos+20])
    footer = apk_bytes[cd_off-24:cd_off]
    magic = footer[8:24]
    
    res = {"v2": False, "v3": False, "play_stamp": False, "certs": []}
    if magic != b'APK Sig Block 42':
        return res

    block_size = struct.unpack('<Q', footer[:8])[0]
    p = cd_off - block_size - 8 + 8

    while p < cd_off - 24:
        pair_len = struct.unpack('<Q', apk_bytes[p:p+8])[0]
        pair_id = struct.unpack('<I', apk_bytes[p+8:p+12])[0]
        pair_data = apk_bytes[p+12:p+8+pair_len]

        if pair_id == 0x7109871a:  # v2
            res["v2"] = True
            if HAS_CRYPTO:
                try:
                    s_len = struct.unpack('<I', pair_data[4:8])[0]
                    sd = pair_data[8:8+s_len]
                    sd_len = struct.unpack('<I', sd[:4])[0]
                    sd_body = sd[4:4+sd_len]
                    dig_len = struct.unpack('<I', sd_body[:4])[0]
                    certs_off = 4 + dig_len
                    certs_len = struct.unpack('<I', sd_body[certs_off:certs_off+4])[0]
                    cp = certs_off + 4
                    while cp < certs_off + 4 + certs_len:
                        c_len = struct.unpack('<I', sd_body[cp:cp+4])[0]
                        c_der = sd_body[cp+4:cp+4+c_len]
                        cert = x509.load_der_x509_certificate(c_der, default_backend())
                        res["certs"].append({
                            "subject": cert.subject.rfc4514_string(),
                            "issuer": cert.issuer.rfc4514_string(),
                            "sha256": cert.fingerprint(cert.signature_hash_algorithm).hex()
                        })
                        cp += 4 + c_len
                except: pass

        elif pair_id == 0xf05368c0:
            res["v3"] = True
        elif pair_id in [0x6dff800d, 0x2b091894, 0x2146444e]:
            res["play_stamp"] = True

        p += 8 + pair_len
    return res

# ==================================================================================================
# Master 10-Layer Universal Forensics Orchestrator
# ==================================================================================================
def run_universal_audit(target_path: str, output_dir: str = None):
    if not os.path.isfile(target_path):
        print(f"[ERROR] Target file does not exist: {target_path}")
        sys.exit(1)

    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(target_path))

    filename = os.path.basename(target_path)
    with open(target_path, 'rb') as f:
        file_bytes = f.read()

    file_size = len(file_bytes)
    hashes = calculate_hashes(file_bytes)
    file_format = detect_file_format(file_bytes, filename)
    overall_entropy = hashes["ssdeep_entropy"]

    print(BANNER)
    print("=" * 80)
    print(f"[*] Target Binary  : {filename}")
    print(f"[*] Architecture   : {file_format}")
    print(f"[*] Byte Count     : {file_size:,} bytes ({file_size / (1024*1024):.2f} MB)")
    print(f"[*] Shannon Entropy: {overall_entropy:.2f} / 8.00 ({'High (Packed / Crypter)' if overall_entropy > 7.15 else 'Standard Unpacked'})")
    print(f"[*] SHA-256 Hash   : {hashes['sha256']}")
    print(f"[*] MD5 Hash       : {hashes['md5']}")
    print("=" * 80)

    # 1. Extract raw strings
    raw_ascii = re.findall(b'[\x20-\x7e]{4,}', file_bytes)
    all_raw_text = " ".join([s.decode('latin1', errors='ignore') for s in raw_ascii])
    raw_urls = re.findall(r'https?://[^\s\'"<>]+', all_raw_text)

    # ----------------------------------------------------------------------------------------------
    # EXECUTION OF THE 10 DEFENSE ENGINES
    # ----------------------------------------------------------------------------------------------
    print("\n[*] [Engine 1/10] Running Built-in YARA APT & Threat Signature Matcher...")
    yara_hits = scan_yara(file_bytes)

    print("[*] [Engine 2/10] Analyzing Shellcode, Syscalls & Memory Injection...")
    mem_hits = scan_memory_dump(file_bytes)

    print("[*] [Engine 3/10] Carving Embedded Firmware & RootFS Filesystems...")
    firmware_hits = scan_firmware(file_bytes)

    print("[*] [Engine 4/10] Auditing Network C2, DGA & DNS Tunneling Endpoints...")
    net_findings = analyze_network_traffic(raw_urls)

    print("[*] [Engine 5/10] Simulating Dynamic Sandbox Runtime & Behavior...")
    sandbox_events = simulate_sandbox_trace(all_raw_text, file_format)

    print("[*] [Engine 6/10] Auditing Anti-Hooking & Generating Dynamic Frida Bypass...")
    anti_hook_hits = audit_anti_hooking(all_raw_text)
    frida_script = generate_frida_bypass_script(os.path.splitext(filename)[0])
    with open(os.path.join(output_dir, 'frida_bypass_hook.js'), 'w', encoding='utf-8') as f:
        f.write(frida_script)

    print("[*] [Engine 7/10] Analyzing Symbolic Branches & Time-Bomb Triggers...")
    symbolic_triggers = analyze_conditional_branches(all_raw_text)

    print("[*] [Engine 8/10] Scanning Bytecode Opcode Sleds & Hooking Trampolines...")
    opcode_findings = scan_opcodes_heuristics(file_bytes, file_format)

    owasp_mobile_findings = []
    apk_info = None

    if file_format == "APK":
        print("[*] [Engine 9/10] Decompiling Android Container & Running OWASP Mobile Audit...")
        manifest_xml = ""
        dex_bytes = b""
        with zipfile.ZipFile(target_path, 'r') as z:
            for n in z.namelist():
                if n == 'AndroidManifest.xml':
                    manifest_xml = decode_axml(z.read(n))
                elif n == 'classes.dex':
                    dex_bytes = z.read(n)

        with open(os.path.join(output_dir, 'decoded_manifest.xml'), 'w', encoding='utf-8') as f:
            f.write(manifest_xml)

        dex_info = parse_dex_file(dex_bytes)
        sig_info = verify_apk_signatures(file_bytes)
        owasp_mobile_findings = audit_owasp_mobile(manifest_xml, dex_info["strings"])
        apk_info = {
            "classes": dex_info["class_count"],
            "methods": dex_info["method_count"],
            "signatures": sig_info
        }

    print("[*] [Engine 10/10] Verifying Air-Gapped Chamber Execution Parameters...")
    chamber = IsolatedExecutionChamber(target_path)

    # Calculate Global Threat Score
    threat_score = 0
    if yara_hits:
        for y in yara_hits:
            threat_score += 40 if y["threat"] == "CRITICAL" else 25
    if mem_hits:
        for m in mem_hits:
            threat_score += 35 if m["severity"] == "CRITICAL" else 20
    if net_findings["dga_candidates"] or net_findings["dns_tunneling_candidates"]:
        threat_score += 30
    if net_findings["cloud_c2_endpoints"]:
        threat_score += 30
    if any(m["severity"] == "CRITICAL" for m in owasp_mobile_findings):
        threat_score += 30
    # In native binaries (PE/ELF/Mach-O), entropy > 7.15 indicates packed crypters
    if overall_entropy > 7.15 and file_format not in ["APK", "ZIP_ARCHIVE"]:
        threat_score += 20
    threat_score = min(100, threat_score)

    verdict = "CLEAN & SAFE" if threat_score == 0 else ("LOW RISK / SUSPICIOUS" if threat_score <= 35 else "HIGH RISK / MALICIOUS")
    print(f"\n[+] Security Verdict: {verdict} (Threat Score: {threat_score}/100)")

    # Generate Full 10-Layer Markdown Report
    generate_master_report({
        "filename": filename,
        "format": file_format,
        "size": file_size,
        "hashes": hashes,
        "entropy": overall_entropy,
        "threat_score": threat_score,
        "verdict": verdict,
        "yara_hits": yara_hits,
        "mem_hits": mem_hits,
        "firmware_hits": firmware_hits,
        "net_findings": net_findings,
        "sandbox_events": sandbox_events,
        "anti_hook_hits": anti_hook_hits,
        "symbolic_triggers": symbolic_triggers,
        "opcode_findings": opcode_findings,
        "owasp_mobile": owasp_mobile_findings,
        "apk_info": apk_info,
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    }, output_dir)

def generate_master_report(d, output_dir):
    report_file = os.path.join(output_dir, 'OstadRESpy_AUDIT_REPORT.md')
    badge_color = "success" if d["threat_score"] == 0 else ("yellow" if d["threat_score"] <= 35 else "critical")

    # Engine 1: YARA
    yara_section = ""
    if d["yara_hits"]:
        yara_lines = "\n".join([f"* ⚠️ **{h['name']}** (Threat: `{h['threat']}` | MITRE: `{h['mitre']}`)" for h in d["yara_hits"]])
        yara_section = f"\n### 🎯 Engine 1: YARA APT & Malware Detections\n{yara_lines}\n"
    else:
        yara_section = "\n### 🎯 Engine 1: YARA APT & Malware Detections\n* ✅ **CLEAN:** No known APT, Ransomware, or Botnet YARA signatures detected.\n"

    # Engine 2: Memory & Shellcode
    mem_section = ""
    if d["mem_hits"]:
        mem_lines = "\n".join([f"* ⚠️ **{m['detection']}** (Severity: `{m['severity']}` | Hits: {m['match_count']})" for m in d["mem_hits"]])
        mem_section = f"\n### 🧠 Engine 2: Memory Forensics & Injection\n{mem_lines}\n"
    else:
        mem_section = "\n### 🧠 Engine 2: Memory Forensics & Injection\n* ✅ **CLEAN:** No reflective PE loaders, Metasploit stagers, or syscall stubs.\n"

    # Engine 3: Firmware
    fw_section = ""
    if d["firmware_hits"]:
        fw_lines = "\n".join([f"* 📦 Offset `{f['offset']}`: **{f['name']}** ({f['category']})" for f in d["firmware_hits"][:8]])
        fw_section = f"\n### ⚙️ Engine 3: Embedded Firmware & RootFS Carving\n{fw_lines}\n"
    else:
        fw_section = "\n### ⚙️ Engine 3: Embedded Firmware & RootFS Carving\n* ℹ️ No embedded SquashFS, CramFS, or U-Boot structures found (Standard application).\n"

    # Engine 4: Network & DGA
    net = d["net_findings"]
    net_lines = []
    if net["dga_candidates"]: net_lines.append(f"* 🚨 **DGA Domains:** {', '.join(net['dga_candidates'][:5])}")
    if net["dns_tunneling_candidates"]: net_lines.append(f"* 📡 **DNS Tunneling Candidates:** {', '.join(net['dns_tunneling_candidates'][:5])}")
    if net["cloud_c2_endpoints"]: net_lines.append(f"* 🌐 **Cloud C2 / Relays:** {', '.join(net['cloud_c2_endpoints'][:5])}")
    net_str = "\n".join(net_lines) if net_lines else "* ✅ **CLEAN:** No DGA domains, DNS tunneling, or unauthorized C2 relays."
    net_section = f"\n### 🌐 Engine 4: Network Forensics & C2 Hunting\n{net_str}\n"

    # Engine 5: OWASP Mobile
    mobile_section = ""
    if d["owasp_mobile"]:
        mob_lines = "\n".join([f"* 📱 **{m['owasp']}** (`{m['severity']}`): {m['detail']}" for m in d["owasp_mobile"]])
        mobile_section = f"\n### 📱 Engine 5: OWASP Mobile Top 10 Security Audit\n{mob_lines}\n"
    elif d["format"] == "APK":
        mobile_section = "\n### 📱 Engine 5: OWASP Mobile Top 10 Security Audit\n* ✅ **PASSED:** No high-risk OWASP mobile vulnerabilities detected.\n"

    # Engine 6: Dynamic Sandbox
    sb_lines = "\n".join([f"* 🔬 **{ev['event']}:** `{', '.join(ev['matches'])}`" for ev in d["sandbox_events"]]) or "* No suspicious dynamic drop triggers observed."
    sb_section = f"\n### 🔬 Engine 6: Dynamic Sandbox Behavior Simulation\n{sb_lines}\n"

    # Engine 7: DBI & Anti-Hooking
    dbi_lines = ", ".join(d["anti_hook_hits"]) or "None detected (App does not resist dynamic instrumentation)."
    dbi_section = f"\n### 💉 Engine 7: Dynamic Binary Instrumentation (DBI) & Hooking\n* **Anti-Hooking Detections:** {dbi_lines}\n* **Auto-Generated Bypass:** Generated `frida_bypass_hook.js` for instant SSL Pinning and Root detection bypass.\n"

    # Engine 8: Symbolic Triggers
    sym_lines = "\n".join([f"* 🧩 {t}" for t in d["symbolic_triggers"]]) or "* No time-bomb or conditional environment gates detected."
    sym_section = f"\n### 🧩 Engine 8: Symbolic Execution & Time-Bomb Triggers\n{sym_lines}\n"

    # Engine 9: Opcode Sleds
    op_lines = "\n".join([f"* 🔍 {o}" for o in d["opcode_findings"]]) or "* Standard compiled opcodes. No NOP sleds or breakpoint traps."
    op_section = f"\n### 🔍 Engine 9: Bytecode Opcode & Sled Analysis\n{op_lines}\n"

    # Engine 10: Isolation
    iso_section = "\n### 🛡️ Engine 10: Air-Gapped Disposable Isolation\n* Verified disposable chamber compatibility. Subprocess throttling parameters initialized.\n"

    md_content = f"""# 🛡️ OstadRESpy Universal Forensic Intelligence Report
### *All-in-One 10-Layer Defense & Threat Analysis Dossier*

[![Tool: OstadRESpy v3.0](https://img.shields.io/badge/Engine-OstadRESpy%20v3.0%20(10--Layer)-blue.svg)](#)
[![Security Verdict](https://img.shields.io/badge/Security%20Verdict-{d['verdict'].replace(' ', '%20')}-{badge_color}.svg)](#)
[![Threat Score](https://img.shields.io/badge/Threat%20Score-{d['threat_score']}%2F100-{badge_color}.svg)](#)
[![Author](https://img.shields.io/badge/Auditor-Ostad%20Rezaul%20Karim-red.svg)](#)
[![Organization](https://img.shields.io/badge/Team-Ostad%20Red%20Team%20Forge-black.svg)](#)

---

## 📌 Target Binary Forensic Dossier

* **Target Artifact:** `{d['filename']}`
* **Detected Format:** `{d['format']}`
* **File Size:** {d['size']:,} bytes ({d['size'] / (1024*1024):.2f} MB)
* **Shannon Entropy:** {d['entropy']} / 8.00 ({'Packed / High' if d['entropy'] > 7.15 else 'Standard Unpacked'})
* **Cryptographic SHA-256:** `{d['hashes']['sha256']}`
* **Cryptographic MD5:** `{d['hashes']['md5']}`
* **Audit Generated:** {d['timestamp']}
* **Final Verdict:** **{d['verdict']} (Threat Score: {d['threat_score']}/100)**

---

## 🏆 Full 10-Layer Defense Engine Results

{yara_section}
{mem_section}
{fw_section}
{net_section}
{mobile_section}
{sb_section}
{dbi_section}
{sym_section}
{op_section}
{iso_section}

---

## 👨‍💻 Auditor & Organization Information

* **Lead Auditor:** **Ostad Rezaul Karim**
* **Title:** Director and Founder
* **Organization:** **Ostad Red Team Forge**
* **Official Inquiries:** `ostadrezaulkarimofficial@gmail.com`
* **Mission:** Providing an all-in-one, top-tier open-source defensive cybersecurity toolkit that replaces 10 disparate external tools with a single unified engine.

---
*Generated automatically by **OstadRESpy v3.0** - All-in-One 10-Layer Cyber Defense Engine.*
"""

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(md_content)
    print(f"[+] All-in-One 10-Layer Defense Dossier Generated: {report_file}")

if __name__ == '__main__':
    script_dir = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(script_dir, 'base.apk')
    if len(sys.argv) > 1:
        target = sys.argv[1]
    run_universal_audit(target, script_dir)
