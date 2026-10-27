#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
====================================================================================================
                        🛡️ OstadRESpy - 1-Click GitHub Pusher
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
  Target Repo  : https://github.com/OstadRezaulKarimRedTeamer/OstadRESpy
====================================================================================================
"""

import os
import sys
from dulwich import porcelain

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

print("=" * 80)
print("     🛡️ OstadRESpy v3.0 - Automated GitHub Publishing Engine")
print("     Author : Ostad Rezaul Karim (Ostad Red Team Forge)")
print("     Target : https://github.com/OstadRezaulKarimRedTeamer/OstadRESpy.git")
print("=" * 80)

# Check for token in args or environment
token = None
if len(sys.argv) > 1:
    token = sys.argv[1].strip()
if not token:
    token = os.environ.get("GITHUB_TOKEN")

if not token:
    print("\n[*] To publish to your GitHub account (OstadRezaulKarimRedTeamer):")
    print("    1. Go to: https://github.com/settings/tokens/new?scopes=repo&description=OstadRESpy")
    print("    2. Click 'Generate token' and copy your Personal Access Token (starts with ghp_)")
    print("-" * 80)
    try:
        token = input("Enter your GitHub Personal Access Token (or paste it here): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Operation cancelled.")
        sys.exit(1)

if not token:
    print("[ERROR] Token cannot be empty!")
    sys.exit(1)

# Ensure empty remote repo exists or push
remote_url = f"https://{token}@github.com/OstadRezaulKarimRedTeamer/OstadRESpy.git"

print("\n[*] Staging any latest changes...")
porcelain.add(CURRENT_DIR)
try:
    porcelain.commit(
        CURRENT_DIR,
        message=b"Update: OstadRESpy v3.0 All-in-One 10-Layer Defense Engine",
        author=b"ostadrezaulkarimhafijahullah-a11y <281227208+ostadrezaulkarimhafijahullah-a11y@users.noreply.github.com>",
        committer=b"ostadrezaulkarimhafijahullah-a11y <281227208+ostadrezaulkarimhafijahullah-a11y@users.noreply.github.com>"
    )
    print("[+] Created updated commit.")
except Exception:
    print("[*] Working tree clean, ready to push.")

print("[*] Pushing branch 'main' to https://github.com/OstadRezaulKarimRedTeamer/OstadRESpy.git...")
try:
    porcelain.push(CURRENT_DIR, remote_url, refspecs=b"refs/heads/main:refs/heads/main")
    print("\n" + "=" * 80)
    print("  🚀 [SUCCESS] OstadRESpy is NOW LIVE on GitHub!")
    print("  🔗 View your repository: https://github.com/OstadRezaulKarimRedTeamer/OstadRESpy")
    print("=" * 80)
except Exception as e:
    err_msg = str(e)
    print(f"\n[!] Push response: {err_msg}")
    if "404" in err_msg or "not found" in err_msg.lower():
        print("\n[NOTE] GitHub requires the repository to be created first:")
        print("1. Go to https://github.com/new")
        print("2. Repository name: OstadRESpy")
        print("3. Leave it Public and do NOT check 'Add README' (keep it completely empty).")
        print("4. Click 'Create repository' and run this script again!")
