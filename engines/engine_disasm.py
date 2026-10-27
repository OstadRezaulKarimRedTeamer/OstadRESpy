# -*- coding: utf-8 -*-
"""
====================================================================================================
               🔍 OstadRESpy Engine 8: Interactive Bytecode & Opcode Disassembler
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

def scan_opcodes_heuristics(data: bytes, file_format: str = "GENERIC_BINARY"):
    findings = []
    
    # In archive containers (e.g. APK, ZIP), raw bytes are compressed zlib streams,
    # so x86 opcode heuristics are only valid for native binaries (PE, ELF, Mach-O).
    if file_format in ["APK", "ZIP_ARCHIVE"]:
        return []

    # 1. NOP Sled detection (Classic buffer overflow / ROP chain indicator)
    if b'\x90' * 32 in data:
        findings.append("NOP Sled Detected (32+ consecutive 0x90 bytes, typical shellcode sled).")

    # 2. INT 3 breakpoint sled (Anti-analysis / Debugger traps)
    if b'\xcc' * 16 in data:
        findings.append("Software Breakpoint Sled (16+ consecutive 0xCC bytes).")

    # 3. Indirect Jumps & Calls (Hooking / Trampolines) in native code
    if file_format in ["WINDOWS_PE", "LINUX_ELF", "MACOS_MACHO"]:
        if b'\xff\x25' in data:
            findings.append("Indirect JMP Table / API Hooking Trampoline (0xFF 0x25 pattern).")

    return findings
