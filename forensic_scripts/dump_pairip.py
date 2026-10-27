import struct

def dump_pairip_details():
    with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\all_raw_strings.txt', 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f]

    pairip_lines = [l for l in lines if 'pairip' in l.lower() or 'license' in l.lower()]
    print(f"Total pairip/license strings: {len(pairip_lines)}")
    for l in pairip_lines[:40]:
        print("  *", l)

dump_pairip_details()
