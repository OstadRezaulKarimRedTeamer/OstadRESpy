import struct

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex', 'rb') as f:
    data = f.read()

# Let's inspect the surrounding bytes and strings of 0x29d6d4 and 0x5340f0
for offset, name in [(0x29d6d4, "sumsub"), (0x5340f0, "shokran")]:
    print(f"\n=== Context for {name} (around {hex(offset)}) ===")
    chunk = data[max(0, offset - 200):min(len(data), offset + 200)]
    # find ascii strings in chunk
    import re
    ascii_strs = re.findall(b'[\x20-\x7e]{3,}', chunk)
    for s in ascii_strs:
        print("  *", s.decode('latin1'))

