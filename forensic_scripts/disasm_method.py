import struct

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex', 'rb') as f:
    data = f.read()

# Let's inspect Method_51408 bytes: 0x29d6b0 - 0x29d726
code = data[0x29d6b0:0x29d726]

# Read uleb128 helper
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

type_ids_size = struct.unpack('<I', data[64:68])[0]
type_ids_off = struct.unpack('<I', data[68:72])[0]
def get_type(idx):
    if idx >= type_ids_size:
        return f"Type_{idx}"
    s_idx = struct.unpack('<I', data[type_ids_off + 4*idx : type_ids_off + 4*idx + 4])[0]
    return get_str(s_idx)

method_ids_size = struct.unpack('<I', data[88:92])[0]
method_ids_off = struct.unpack('<I', data[92:96])[0]
def get_method_name(idx):
    if idx >= method_ids_size:
        return f"Method_{idx}"
    class_idx, proto_idx, name_idx = struct.unpack('<HHI', data[method_ids_off + 8*idx : method_ids_off + 8*idx + 8])
    return f"{get_type(class_idx)}->{get_str(name_idx)}"

# Simple dalvik disassembler for this method
p = 0
while p < len(code):
    op = code[p]
    if op == 0x1a: # const-string vAA, string@BBBB
        reg = code[p+1]
        s_idx = struct.unpack('<H', code[p+2:p+4])[0]
        print(f"{hex(0x29d6b0 + p)}: const-string v{reg}, \"{get_str(s_idx)}\"")
        p += 4
    elif op in [0x6e, 0x6f, 0x70, 0x71, 0x72]: # invoke-kind {vC, vD...}, meth@BBBB
        meth_idx = struct.unpack('<H', code[p+2:p+4])[0]
        print(f"{hex(0x29d6b0 + p)}: invoke (op={hex(op)}) {get_method_name(meth_idx)}")
        p += 6
    elif op in [0x74, 0x75, 0x76, 0x77, 0x78]: # invoke-kind/range
        meth_idx = struct.unpack('<H', code[p+2:p+4])[0]
        print(f"{hex(0x29d6b0 + p)}: invoke/range {get_method_name(meth_idx)}")
        p += 6
    else:
        # advance by 2
        p += 2
