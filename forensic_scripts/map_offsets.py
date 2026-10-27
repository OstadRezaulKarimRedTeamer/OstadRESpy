import struct

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex', 'rb') as f:
    data = f.read()

# Helper to read uleb128
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

class_defs_size = struct.unpack('<I', data[96:100])[0]
class_defs_off = struct.unpack('<I', data[100:104])[0]

# Find which method spans target offsets
target_offsets = [0x29d6d4, 0x5340f0]

for i in range(class_defs_size):
    class_idx, access_flags, superclass_idx, interfaces_off, source_file_idx, annotations_off, class_data_off, static_values_off = struct.unpack('<IIIIIIII', data[class_defs_off + 32*i : class_defs_off + 32*i + 32])
    if class_data_off == 0:
        continue
    p = class_data_off
    static_fields_size, p = read_uleb128(p)
    instance_fields_size, p = read_uleb128(p)
    direct_methods_size, p = read_uleb128(p)
    virtual_methods_size, p = read_uleb128(p)

    # skip fields
    for _ in range(static_fields_size):
        _, p = read_uleb128(p)
        _, p = read_uleb128(p)
    for _ in range(instance_fields_size):
        _, p = read_uleb128(p)
        _, p = read_uleb128(p)

    # read methods
    method_idx = 0
    for _ in range(direct_methods_size + virtual_methods_size):
        diff, p = read_uleb128(p)
        method_idx += diff
        access, p = read_uleb128(p)
        code_off, p = read_uleb128(p)
        if code_off > 0:
            # code_item
            insns_size = struct.unpack('<I', data[code_off+12:code_off+16])[0]
            start = code_off + 16
            end = start + insns_size * 2
            for tgt in target_offsets:
                if start <= tgt < end:
                    print(f"Offset {hex(tgt)} is in method: {get_method_name(method_idx)} (insns: {start:#x} - {end:#x})")
                    if source_file_idx != 0xFFFFFFFF:
                        print(f"  Source file: {get_str(source_file_idx)}")
