import struct

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex', 'rb') as f:
    data = f.read()

# Helper
def read_uleb128(p):
    val = 0
    shift = 0
    while True:
        b = data[p]
        p += 1
        val |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            break
    return val, p

string_ids_size = struct.unpack('<I', data[56:60])[0]
string_ids_off = struct.unpack('<I', data[60:64])[0]
def get_str(idx):
    if idx >= string_ids_size:
        return f"Str_{idx}"
    off = struct.unpack('<I', data[string_ids_off + 4*idx : string_ids_off + 4*idx + 4])[0]
    p = off
    _, p = read_uleb128(p)
    null_pos = data.find(b'\x00', p)
    return data[p:null_pos].decode('latin1', errors='replace')

# Let's inspect instructions in Lk53-><clinit> (0x533cb4 - 0x5342c6)
code = data[0x533cb4:0x5342c6]
# Search for const-string opcodes 0x1a
strings_found = []
for p in range(0, len(code)-4, 2):
    op = code[p]
    if op == 0x1a:
        s_idx = struct.unpack('<H', code[p+2:p+4])[0]
        strings_found.append(get_str(s_idx))

print("=== Strings in Lk53 (App Config / Constants) ===")
for s in strings_found:
    print("  *", repr(s))

# Do the same for Method_51408 (0x29d6b0 - 0x29d726)
code2 = data[0x29d6b0:0x29d726]
strings_found2 = []
for p in range(0, len(code2)-4, 2):
    op = code2[p]
    if op == 0x1a:
        s_idx = struct.unpack('<H', code2[p+2:p+4])[0]
        strings_found2.append(get_str(s_idx))

print("\n=== Strings in Method_51408 ===")
for s in strings_found2:
    print("  *", repr(s))
