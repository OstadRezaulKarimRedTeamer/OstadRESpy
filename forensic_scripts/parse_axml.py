import struct
import sys

def parse_axml(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()

    header_type, header_size, file_size = struct.unpack('<HHI', data[:8])
    if header_type != 0x0003:
        print(f"Not an AXML file (header: {hex(header_type)})")
        return

    offset = 8
    strings = []
    xml_output = []
    namespaces = {}
    indent = 0

    while offset < len(data):
        chunk_type, chunk_header_size, chunk_size = struct.unpack('<HHI', data[offset:offset+8])
        chunk_data = data[offset:offset+chunk_size]

        if chunk_type == 0x0001:  # String Pool
            string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIII', chunk_data[8:28])
            is_utf8 = bool(flags & (1 << 8))
            offsets = [struct.unpack('<I', chunk_data[28 + 4*i : 32 + 4*i])[0] for i in range(string_count)]
            str_data = chunk_data[strings_start:]

            strings = []
            for off in offsets:
                if is_utf8:
                    # UTF-8 string: [u16/u8 length bytes][utf-8 bytes]\0
                    p = off
                    # skip char length
                    if str_data[p] & 0x80:
                        p += 2
                    else:
                        p += 1
                    # byte length
                    if str_data[p] & 0x80:
                        length = ((str_data[p] & 0x7f) << 8) | str_data[p+1]
                        p += 2
                    else:
                        length = str_data[p]
                        p += 1
                    s = str_data[p:p+length].decode('utf-8', errors='replace')
                    strings.append(s)
                else:
                    # UTF-16 string
                    p = off
                    length = struct.unpack('<H', str_data[p:p+2])[0]
                    if length & 0x8000:
                        length = ((length & 0x7fff) << 16) | struct.unpack('<H', str_data[p+2:p+4])[0]
                        p += 4
                    else:
                        p += 2
                    s = str_data[p:p+length*2].decode('utf-16le', errors='replace')
                    strings.append(s)

        elif chunk_type == 0x0180:  # Resource Map
            pass  # Resource IDs array

        elif chunk_type == 0x0100:  # Start Namespace
            line_num, comment_idx, prefix_idx, uri_idx = struct.unpack('<IIii', chunk_data[8:24])
            prefix = strings[prefix_idx] if prefix_idx >= 0 else ""
            uri = strings[uri_idx] if uri_idx >= 0 else ""
            namespaces[prefix] = uri

        elif chunk_type == 0x0101:  # End Namespace
            pass

        elif chunk_type == 0x0102:  # Start Tag
            line_num, comment_idx, ns_idx, name_idx, attr_start, attr_size, attr_count, id_idx, class_idx, style_idx = struct.unpack('<IIiiHHHHHH', chunk_data[8:36])
            tag_name = strings[name_idx] if name_idx >= 0 else "unknown"
            attrs = []
            attr_offset = 36
            for _ in range(attr_count):
                a_ns, a_name, a_val_str, a_type, a_data = struct.unpack('<iiIIi', chunk_data[attr_offset:attr_offset+20])
                attr_offset += 20
                attr_name = strings[a_name] if a_name >= 0 else ""
                if a_val_str != 0xFFFFFFFF and a_val_str < len(strings):
                    val = strings[a_val_str]
                else:
                    # check type
                    data_type = a_type >> 24
                    if data_type == 0x12: # boolean
                        val = "true" if a_data != 0 else "false"
                    elif data_type == 0x10: # int
                        val = str(a_data)
                    elif data_type == 0x11: # hex int
                        val = hex(a_data)
                    elif data_type == 0x01: # reference
                        val = f"@0x{a_data:08x}"
                    else:
                        val = str(a_data)
                attrs.append(f'{attr_name}="{val}"')

            attr_str = (" " + " ".join(attrs)) if attrs else ""
            xml_output.append("  " * indent + f"<{tag_name}{attr_str}>")
            indent += 1

        elif chunk_type == 0x0103:  # End Tag
            line_num, comment_idx, ns_idx, name_idx = struct.unpack('<IIii', chunk_data[8:24])
            tag_name = strings[name_idx] if name_idx >= 0 else "unknown"
            indent = max(0, indent - 1)
            xml_output.append("  " * indent + f"</{tag_name}>")

        offset += chunk_size

    return "\n".join(xml_output)

if __name__ == '__main__':
    manifest_xml = parse_axml(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\extracted\AndroidManifest.xml')
    with open(r'C:\Users\USER\.gemini\antigravity\scratch\apk_analysis\decoded_manifest.xml', 'w', encoding='utf-8') as f:
        f.write(manifest_xml)
    print("Manifest decoded successfully! Lines:", len(manifest_xml.splitlines()))
