# -*- coding: utf-8 -*-
"""
====================================================================================================
                        🛡️ OstadRESpy Engine 1: Built-in YARA & Threat Signature Scanner
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import re

# Production-grade YARA-like signatures for Top APTs, Ransomware, and Exploitation Frameworks
RULES = [
    {
        "id": "APT_COBALT_STRIKE_BEACON",
        "name": "Cobalt Strike Beacon / Named Pipe",
        "threat": "CRITICAL",
        "mitre": "T1071.001 - Multi-Stage Command and Control",
        "patterns": [
            rb"%s as %s\\%s: %d",
            rb"\\\\\.\\pipe\\msagent_",
            rb"\\\\\.\\pipe\\status_",
            rb"I am an agent of your destruction",
            rb"beacon\.dll",
            rb"ReflectiveLoader"
        ]
    },
    {
        "id": "RANSOMWARE_GENERIC_CRYPTER",
        "name": "Generic Ransomware Crypto & Shadow Copy Deletion",
        "threat": "CRITICAL",
        "mitre": "T1486 - Data Encrypted for Impact",
        "patterns": [
            rb"vssadmin(\.exe)?\s+delete\s+shadows",
            rb"wmic\s+shadowcopy\s+delete",
            rb"bcdedit\s+/set\s+\{default\}\s+recoveryenabled\s+No",
            rb"wbadmin\s+delete\s+catalog\s+-quiet",
            rb"HOW_TO_DECRYPT",
            rb"YOUR_FILES_ARE_ENCRYPTED",
            rb"DECRYPT_FILES\.(txt|html)",
            rb"all your files have been encrypted",
            rb"restore_files_instructions",
            rb"README_DECRYPT"
        ]
    },
    {
        "id": "METASPLOIT_METERPRETER_STAGER",
        "name": "Metasploit Meterpreter Reverse Stager",
        "threat": "HIGH",
        "mitre": "T1059 - Command and Scripting Interpreter",
        "patterns": [
            rb"/meterpreter_",
            rb"metsrv\.dll",
            rb"stdapi_",
            rb"\x6a\x00\x53\xff\xd5",  # call ebp shellcode stager pattern
            rb"core_channel_open"
        ]
    },
    {
        "id": "PEGASUS_SPYWARE_INDICATOR",
        "name": "Pegasus Spyware / Mobile Surveillance Artifact",
        "threat": "CRITICAL",
        "mitre": "T1430 - Location / Communication Surveillance",
        "patterns": [
            rb"bh_recording",
            rb"call_recorder_svc",
            rb"libaudio_flinger_hook\.so",
            rb"/data/local/tmp/pegasus",
            rb"com\.network\.sniffer"
        ]
    },
    {
        "id": "MIRAI_IOT_BOTNET",
        "name": "Mirai IoT DDoS Botnet Variant",
        "threat": "HIGH",
        "mitre": "T1498 - Network Denial of Service",
        "patterns": [
            rb"/bin/busybox\s+wget",
            rb"/bin/busybox\s+tftp",
            rb"POST /cdn-cgi/",
            rb"dvrHelper",
            rb"attack_udp_generic"
        ]
    },
    {
        "id": "REVERSE_SHELL_PAYLOADS",
        "name": "Interactive Reverse TCP Shell Injection",
        "threat": "HIGH",
        "mitre": "T1059.004 - Unix Shell Spawning",
        "patterns": [
            rb"/bin/sh\s+-i\s+>&",
            rb"nc\s+-e\s+/bin/",
            rb"socat\s+exec:",
            rb"rm\s+/tmp/f;mkfifo\s+/tmp/f",
            rb"pty\.spawn\(\"/bin/"
        ]
    },
    {
        "id": "POWERSHELL_OBFUSCATION_STAGER",
        "name": "Obfuscated PowerShell Download Cradle",
        "threat": "HIGH",
        "mitre": "T1059.001 - PowerShell Remote Cradle",
        "patterns": [
            rb"\[System\.Convert\]::FromBase64String",
            rb"New-Object\s+Net\.WebClient",
            rb"DownloadData\(",
            rb"\[System\.Reflection\.Assembly\]::Load\(",
            rb"Invoke-Mimikatz"
        ]
    }
]

def scan_yara(data: bytes):
    results = []
    for rule in RULES:
        matched = []
        for pat in rule["patterns"]:
            if re.search(pat, data, re.IGNORECASE):
                matched.append(pat.decode('latin1', errors='ignore'))
        if matched:
            results.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "threat": rule["threat"],
                "mitre": rule["mitre"],
                "matches": matched
            })
    return results
