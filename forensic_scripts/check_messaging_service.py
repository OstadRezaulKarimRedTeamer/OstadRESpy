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

type_ids_size = struct.unpack('<I', data[64:68])[0]
type_ids_off = struct.unpack('<I', data[68:72])[0]
def get_type(idx):
    if idx >= type_ids_size:
        return f"Type_{idx}"
    s_idx = struct.unpack('<I', data[type_ids_off + 4*idx : type_ids_off + 4*idx + 4])[0]
    return get_str(s_idx)

class_defs_size = struct.unpack('<I', data[96:100])[0]
class_defs_off = struct.unpack('<I', data[100:104])[0]

for i in range(class_defs_size):
    class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack('<IIIIIIII', data[class_defs_off + 32*i : class_defs_off + 32*i + 32])
    cname = get_type(class_idx)
    if 'AlfafaaMessagingService' in cname:
        print(f"Class: {cname}")
        if class_data_off > 0:
            p = class_data_off
            static_fields_size, p = read_uleb128(p)
            instance_fields_size, p = read_uleb128(p)
            direct_methods_size, p = read_uleb128(p)
            virtual_methods_size, p = read_uleb128(p)
            for _ in range(static_fields_size + instance_fields_size):
                _, p = read_uleb128(p)
                _, p = read_uleb128(p)
            for _ in range(direct_methods_size + virtual_methods_size):
                _, p = read_uleb128(p)
                _, p = read_uleb128(p)
                code_off, p = read_uleb128(p)
                if code_off > 0:
                    insns_size = struct.unpack('<I', data[code_off+12:code_off+16])[0]
                    code_b = data[code_off+16:code_off+16+insns_size*2]
                    for cp in range(0, len(code_b)-4, 2):
                        if code_b[cp] == 0x1a:
                            s_idx = struct.unpack('<H', code_b[cp+2:cp+4])[0]
                            print("  MessagingService String:", repr(get_str(s_idx)))
