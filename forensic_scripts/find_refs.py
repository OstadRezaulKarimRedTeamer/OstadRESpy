import struct

with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\classes.dex', 'rb') as f:
    data = f.read()

# Let's search for string indices of "https://api.sumsub.com" and "https://wallet.shokran.io"
# Read string table
string_ids_size = struct.unpack('<I', data[56:60])[0]
string_ids_off = struct.unpack('<I', data[60:64])[0]

def get_str(idx):
    off = struct.unpack('<I', data[string_ids_off + 4*idx : string_ids_off + 4*idx + 4])[0]
    p = off
    # skip uleb128
    while data[p] & 0x80:
        p += 1
    p += 1
    null_pos = data.find(b'\x00', p)
    return data[p:null_pos].decode('latin1', errors='replace')

sumsub_idx = None
shokran_idx = None
for i in range(string_ids_size):
    s = get_str(i)
    if "api.sumsub.com" in s:
        sumsub_idx = i
        print(f"api.sumsub.com string idx: {i} ({s})")
    if "wallet.shokran.io" in s:
        shokran_idx = i
        print(f"wallet.shokran.io string idx: {i} ({s})")

# Let's search where these string IDs are used (const-string opcodes 0x1a or const-string/jumbo 0x1b)
# In Dalvik bytecode:
# 1A 00 [string_id_16] (const-string vAA, string@BBBB)
# 1B 00 [string_id_32] (const-string/jumbo vAA, string@BBBBBBBB)

for name, s_idx in [("sumsub", sumsub_idx), ("shokran", shokran_idx)]:
    if s_idx is None:
        continue
    # search pattern
    target_16 = struct.pack('<H', s_idx)
    target_32 = struct.pack('<I', s_idx)
    pos = 0
    found = 0
    while True:
        pos = data.find(target_16, pos)
        if pos == -1:
            break
        # check if opcode before or near
        # In 1A AA BB BB: opcode is at pos-2
        if pos >= 2 and data[pos-2] == 0x1a:
            print(f"Found const-string for {name} at offset {hex(pos-2)}")
            found += 1
        pos += 2
    print(f"Total const-string references for {name}: {found}")
