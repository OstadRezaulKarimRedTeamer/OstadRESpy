# -*- coding: utf-8 -*-
"""
====================================================================================================
               📱 OstadRESpy Engine 2: OWASP Mobile Top 10 Automated Security Auditor
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import re

def audit_owasp_mobile(manifest_xml: str, raw_strings: list):
    findings = []
    text_blob = " ".join(raw_strings)

    # M1: Insecure Credentials & Hardcoded API Keys
    key_patterns = [
        ("AWS Access Key", r'AKIA[0-9A-Z]{16}'),
        ("Google API Key", r'AIza[0-9A-Za-z\\-_]{35}'),
        ("Firebase Database URL", r'https://[a-z0-9-]+\.firebaseio\.com'),
        ("RSA Private Key Header", r'-----BEGIN (?:RSA )?PRIVATE KEY-----')
    ]
    for key_name, pat in key_patterns:
        matches = re.findall(pat, text_blob)
        if matches:
            findings.append({
                "owasp": "M1 - Improper Credential Usage / Hardcoded Secret",
                "severity": "HIGH",
                "detail": f"Discovered hardcoded {key_name} in bytecode: {matches[0][:20]}..."
            })

    # M2: Insecure Data Storage
    if "MODE_WORLD_READABLE" in text_blob or "MODE_WORLD_WRITEABLE" in text_blob:
        findings.append({
            "owasp": "M2 - Insecure Data Storage",
            "severity": "HIGH",
            "detail": "Application creates world-readable/writable files accessible by other rogue apps."
        })

    # M3: Insecure Communication & Cleartext HTTP
    if 'android:usesCleartextTraffic="true"' in manifest_xml:
        findings.append({
            "owasp": "M3 - Insecure Communication",
            "severity": "HIGH",
            "detail": "Application explicitly allows unencrypted cleartext HTTP traffic across all domains."
        })
    if "TrustAllSSLCertificates" in text_blob or "NullTrustManager" in text_blob or "ALLOW_ALL_HOSTNAME_VERIFIER" in text_blob:
        findings.append({
            "owasp": "M3 - Insecure Communication (Disabled SSL Validation)",
            "severity": "CRITICAL",
            "detail": "Application disables TLS/SSL certificate validation, making it vulnerable to MITM attacks."
        })

    # M4: Weak Cryptography
    if "AES/ECB" in text_blob or "DES/" in text_blob or "RC4" in text_blob:
        findings.append({
            "owasp": "M4 - Inadequate Cryptography",
            "severity": "MEDIUM",
            "detail": "Application utilizes obsolete/insecure cryptographic ciphers (AES/ECB, DES, or RC4)."
        })

    # M5: Exported Components without Protection
    exported_activities = re.findall(r'<activity[^>]+android:exported="true"[^>]*>', manifest_xml)
    if len(exported_activities) > 3:
        findings.append({
            "owasp": "M5 - Insecure Authorization / Exported Components",
            "severity": "MEDIUM",
            "detail": f"{len(exported_activities)} Activities are exported to external apps without permission guards."
        })

    # M7: Client Code Quality & Debuggability
    if 'android:debuggable="true"' in manifest_xml:
        findings.append({
            "owasp": "M7 - Insufficient Binary Protection (Debuggable)",
            "severity": "CRITICAL",
            "detail": "APK has android:debuggable enabled, allowing any attacker to attach gdb/jdb and read memory."
        })
    if 'allowBackup="true"' in manifest_xml:
        findings.append({
            "owasp": "M7 - Client Code Quality (ADB Backup Enabled)",
            "severity": "LOW",
            "detail": "Application data can be extracted over ADB backup without root access."
        })

    return findings
