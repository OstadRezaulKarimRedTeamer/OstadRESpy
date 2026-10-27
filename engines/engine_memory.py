# -*- coding: utf-8 -*-
"""
====================================================================================================
               🧠 OstadRESpy Engine 4: Live Memory Forensics & Shellcode Injection Hunter
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import re

SHELLCODE_PATTERNS = [
    (re.compile(b'\xfc\xe8[\x00-\xff]{4}\x60'), "Metasploit Universal Reverse Shellcode Prologue (Block API)", "CRITICAL"),
    (re.compile(b'\x4c\x8b\xd1\xb8[\x00-\xff]{2}\x00\x00\x0f\x05'), "x64 Direct Syscall Stub (EDR Unhooking / Syscall Evasion)", "HIGH"),
    (re.compile(b'\xe8\x00\x00\x00\x00\x58'), "x86/x64 GetPC Delta Pointer (Position Independent Shellcode)", "MEDIUM"),
    (re.compile(b'\x6a\x00\x68[\x00-\xff]{4}\x53\xff\xd5'), "Reverse TCP Socket Shellcode Stager", "HIGH"),
    (re.compile(b'MZ[\x00-\xff]{58}\x00\x00\x00\x00[\x00-\xff]{60}This program cannot be run in DOS mode'), "Reflective DLL / Injected PE Embedded in Memory", "CRITICAL")
]

def scan_memory_dump(data: bytes):
    findings = []
    for pattern, name, severity in SHELLCODE_PATTERNS:
        matches = [m.start() for m in pattern.finditer(data)]
        if matches:
            findings.append({
                "detection": name,
                "severity": severity,
                "match_count": len(matches),
                "offsets": [hex(o) for o in matches[:5]]
            })
    return findings
