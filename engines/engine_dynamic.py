# -*- coding: utf-8 -*-
"""
====================================================================================================
               🔬 OstadRESpy Engine 5: Dynamic Sandbox Runtime & Behavior Tracer
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import re

def simulate_sandbox_trace(raw_text: str, file_format: str):
    events = []
    
    fs_triggers = [
        ("File Drop Attempt", [r'\.exe\b', r'\.dll\b', r'\.bat\b', r'\.vbs\b', r'\.ps1\b', r'AppData\\Local\\Temp', r'/data/local/tmp']),
        ("Process Execution", [r'\bCreateProcess[AW]?\b', r'\bShellExecute[AW]?\b', r'\bexecve\b', r'\bfork\(', r'Runtime\.getRuntime\(\)\.exec']),
        ("Registry Persistence", [r'CurrentVersion\\Run\b', r'CurrentVersion\\RunOnce\b', r'AppInit_DLLs\b']),
        ("Network Beaconing", [r'\bInternetConnect[AW]?\b', r'\bHttpOpenRequest[AW]?\b', r'\bconnect\(', r'\bsocket\(']),
        ("Evasion / Sleep Loop", [r'\bSleep\(', r'\bSleepEx\b', r'\bNtDelayExecution\b', r'\bWaitForSingleObject\b'])
    ]

    for event_name, patterns in fs_triggers:
        hits = []
        for pat in patterns:
            found = re.findall(pat, raw_text, re.IGNORECASE)
            if found:
                hits.extend(found)
        if hits:
            events.append({
                "event": event_name,
                "matches": list(set(hits))[:4]
            })

    return events
