#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================================================
                        🛡️ OstadRESpy Cyberpunk Web GUI Server
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
  Contact      : ostadrezaulkarimofficial@gmail.com
====================================================================================================
"""

import os
import sys
import json
import tempfile
import webbrowser
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
import email
from email import policy
from email.parser import BytesParser

# Ensure path to current directory
if getattr(sys, 'frozen', False):
    CURRENT_DIR = sys._MEIPASS
    BASE_DIR = os.path.dirname(sys.executable)
else:
    CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
    BASE_DIR = CURRENT_DIR

if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ostadrespy import (
    calculate_hashes, detect_file_format, decode_axml,
    parse_dex_file, verify_apk_signatures, IsolatedExecutionChamber,
    scan_yara, scan_memory_dump, scan_firmware, analyze_network_traffic,
    simulate_sandbox_trace, audit_anti_hooking, generate_frida_bypass_script,
    analyze_conditional_branches, scan_opcodes_heuristics, audit_owasp_mobile,
    generate_master_report
)
import zipfile
import re
from datetime import datetime, timezone
from ostadbitdiff import run_bitdiff

PORT = 5050
HOST = '0.0.0.0'

def parse_multipart(handler):
    content_type = handler.headers.get('Content-Type', '')
    if 'multipart/form-data' not in content_type:
        return {}
    content_length = int(handler.headers.get('Content-Length', 0))
    body = handler.rfile.read(content_length)

    # Use email parser for standard-compliant multipart parsing
    headers = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode('latin1')
    msg = BytesParser(policy=policy.default).parsebytes(headers + body)
    files = {}
    for part in msg.iter_parts():
        filename = part.get_filename()
        name = part.get_param('name', header='content-disposition')
        payload = part.get_payload(decode=True)
        if name and payload:
            files[name] = {
                "filename": filename or "target.bin",
                "content": payload
            }
    return files

class CyberGUIHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress noisy standard request logging
        pass

    def do_GET(self):
        if self.path in ['/', '/index.html']:
            index_path = os.path.join(CURRENT_DIR, 'web', 'index.html')
            if not os.path.exists(index_path):
                self.send_error(404, "Web UI not found")
                return
            with open(index_path, 'rb') as f:
                data = f.read()
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        elif self.path in ['/logo.jpg', '/assets/logo.jpg']:
            logo_path = os.path.join(CURRENT_DIR, 'logo.jpg')
            if os.path.exists(logo_path):
                with open(logo_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'image/jpeg')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404)

        elif self.path == '/manifest.json':
            m_path = os.path.join(CURRENT_DIR, 'web', 'manifest.json')
            if os.path.exists(m_path):
                with open(m_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404)

        elif self.path == '/api/download_frida':
            frida_path = os.path.join(BASE_DIR, 'frida_bypass_hook.js')
            if os.path.exists(frida_path):
                with open(frida_path, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript')
                self.send_header('Content-Disposition', 'attachment; filename="frida_bypass_hook.js"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404, "Frida script not generated yet")
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/api/scan':
            files = parse_multipart(self)
            target = files.get('file')
            if not target:
                self.send_json({"error": "No file uploaded"}, status=400)
                return

            filename = target["filename"]
            file_bytes = target["content"]
            file_size = len(file_bytes)

            hashes = calculate_hashes(file_bytes)
            file_format = detect_file_format(file_bytes, filename)
            overall_entropy = hashes["ssdeep_entropy"]

            raw_ascii = re.findall(b'[\x20-\x7e]{4,}', file_bytes)
            all_raw_text = " ".join([s.decode('latin1', errors='ignore') for s in raw_ascii])
            raw_urls = re.findall(r'https?://[^\s\'"<>]+', all_raw_text)

            yara_hits = scan_yara(file_bytes)
            mem_hits = scan_memory_dump(file_bytes)
            firmware_hits = scan_firmware(file_bytes)
            net_findings = analyze_network_traffic(raw_urls)
            sandbox_events = simulate_sandbox_trace(all_raw_text, file_format)
            anti_hook_hits = audit_anti_hooking(all_raw_text)

            frida_script = generate_frida_bypass_script(os.path.splitext(filename)[0])
            with open(os.path.join(BASE_DIR, 'frida_bypass_hook.js'), 'w', encoding='utf-8') as f:
                f.write(frida_script)

            symbolic_triggers = analyze_conditional_branches(all_raw_text)
            opcode_findings = scan_opcodes_heuristics(file_bytes, file_format)

            owasp_mobile_findings = []
            apk_info = None

            if file_format == "APK":
                manifest_xml = ""
                dex_bytes = b""
                try:
                    import io
                    with zipfile.ZipFile(io.BytesIO(file_bytes), 'r') as z:
                        for n in z.namelist():
                            if n == 'AndroidManifest.xml':
                                manifest_xml = decode_axml(z.read(n))
                            elif n == 'classes.dex':
                                dex_bytes = z.read(n)
                except Exception:
                    pass

                dex_info = parse_dex_file(dex_bytes)
                sig_info = verify_apk_signatures(file_bytes)
                owasp_mobile_findings = audit_owasp_mobile(manifest_xml, dex_info["strings"])
                apk_info = {
                    "classes": dex_info["class_count"],
                    "methods": dex_info["method_count"],
                    "signatures": sig_info
                }

            # Threat score
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
            if overall_entropy > 7.15 and file_format not in ["APK", "ZIP_ARCHIVE"]:
                threat_score += 20
            threat_score = min(100, threat_score)

            verdict = "CLEAN & SAFE" if threat_score == 0 else ("LOW RISK / SUSPICIOUS" if threat_score <= 35 else "HIGH RISK / MALICIOUS")

            # Generate markdown report
            dossier = {
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
            }
            generate_master_report(dossier, BASE_DIR)

            with open(os.path.join(BASE_DIR, 'OstadRESpy_AUDIT_REPORT.md'), 'r', encoding='utf-8') as f:
                report_md = f.read()

            dossier["report_markdown"] = report_md
            self.send_json(dossier)

        elif self.path == '/api/diff':
            files = parse_multipart(self)
            fA = files.get('fileA')
            fB = files.get('fileB')
            if not fA or not fB:
                self.send_json({"error": "Two files required for diff"}, status=400)
                return

            temp_dir = tempfile.mkdtemp(prefix="ostad_diff_")
            pA = os.path.join(temp_dir, fA["filename"])
            pB = os.path.join(temp_dir, fB["filename"])
            with open(pA, 'wb') as f: f.write(fA["content"])
            with open(pB, 'wb') as f: f.write(fB["content"])

            try:
                diff_res = run_bitdiff(pA, pB, BASE_DIR)
                with open(os.path.join(BASE_DIR, 'OstadBitDiff_REPORT.md'), 'r', encoding='utf-8') as f:
                    diff_md = f.read()
                diff_res["report_markdown"] = diff_md
                self.send_json(diff_res)
            finally:
                import shutil
                shutil.rmtree(temp_dir, ignore_errors=True)

    def send_json(self, data, status=200):
        body = json.dumps(data).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

def main():
    server = HTTPServer((HOST, PORT), CyberGUIHandler)
    url = f"http://localhost:{PORT}"
    print(f"[*] OstadRESpy Cyberpunk HUD running at: {url}")
    print("[*] Opening your default web browser...")
    threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("[*] Server stopped.")

if __name__ == '__main__':
    main()
