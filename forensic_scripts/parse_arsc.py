import struct

def parse_arsc(arsc_path):
    with open(arsc_path, 'rb') as f:
        data = f.read()

    # Read global string pool
    # RES_TABLE_TYPE header is 12 bytes: type (2), header_size (2), size (4), package_count (4)
    # Next chunk is string pool
    chunk_type, chunk_hdr, chunk_size = struct.unpack('<HHI', data[12:20])
    if chunk_type == 0x0001:
        str_cnt, style_cnt, flags, str_start, style_start = struct.unpack('<IIIII', data[20:40])
        is_utf8 = bool(flags & (1 << 8))
        offsets = [struct.unpack('<I', data[40 + 4*i : 44 + 4*i])[0] for i in range(str_cnt)]
        pool_base = 12 + str_start
        strings = []
        for off in offsets:
            p = pool_base + off
            if is_utf8:
                if data[p] & 0x80:
                    p += 2
                else:
                    p += 1
                if data[p] & 0x80:
                    length = ((data[p] & 0x7f) << 8) | data[p+1]
                    p += 2
                else:
                    length = data[p]
                    p += 1
                s = data[p:p+length].decode('utf-8', errors='replace')
                strings.append(s)
            else:
                length = struct.unpack('<H', data[p:p+2])[0]
                p += 2
                s = data[p:p+length*2].decode('utf-16le', errors='replace')
                strings.append(s)
        return strings
    return []

strings = parse_arsc(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\resources.arsc')
print(f"ARSC string count: {len(strings)}")
for s in strings:
    if any(k in s.lower() for k in ['alfafaa', 'app_name', 'islam', 'social', 'community', 'version']):
        print("  ->", s)
