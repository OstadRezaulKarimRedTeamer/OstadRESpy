import glob
import subprocess
import os

# Check META-INF signatures
meta_files = glob.glob(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\META-INF\*')
print("META-INF files:")
for mf in meta_files:
    print(" ", os.path.basename(mf), os.path.getsize(mf), "bytes")

# Check where root check strings appear
with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
    lines = [line.strip() for line in f]

root_idx = [i for i, l in enumerate(lines) if '/system/xbin/su' in l or 'Superuser.apk' in l]
print("\nRoot check context:")
for idx in root_idx:
    start = max(0, idx - 5)
    end = min(len(lines), idx + 6)
    print("--- Context ---")
    for j in range(start, end):
        print(f"  {lines[j]}")

# Check getDeviceId context
dev_idx = [i for i, l in enumerate(lines) if 'getDeviceId' in l]
print("\ngetDeviceId context:")
for idx in dev_idx:
    start = max(0, idx - 5)
    end = min(len(lines), idx + 6)
    print("--- Context ---")
    for j in range(start, end):
        print(f"  {lines[j]}")

# Check getRunningAppProcesses context
proc_idx = [i for i, l in enumerate(lines) if 'getRunningAppProcesses' in l]
print("\ngetRunningAppProcesses context:")
for idx in proc_idx:
    start = max(0, idx - 5)
    end = min(len(lines), idx + 6)
    print("--- Context ---")
    for j in range(start, end):
        print(f"  {lines[j]}")
