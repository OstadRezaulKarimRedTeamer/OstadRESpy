# -*- coding: utf-8 -*-
"""
====================================================================================================
               ⚙️ OstadRESpy Engine 3: Embedded Firmware & Binary Image Carver
====================================================================================================
  Author       : Ostad Rezaul Karim (Director, Ostad Red Team Forge)
====================================================================================================
"""

import struct

FIRMWARE_SIGNATURES = [
    (b'\x27\x05\x19\x56', "U-Boot Image Header", "Firmware Bootloader"),
    (b'hsqs', "SquashFS Little-Endian Filesystem", "Compressed RootFS"),
    (b'sqsh', "SquashFS Big-Endian Filesystem", "Compressed RootFS"),
    (b'\x28\xcd\x3d\x45', "CramFS Filesystem Header", "Embedded Linux FS"),
    (b'\x19\x85\x20\x03', "JFFS2 Cleanmarker (Big-Endian)", "NAND/NOR Flash Storage"),
    (b'\x85\x19\x03\x20', "JFFS2 Cleanmarker (Little-Endian)", "NAND/NOR Flash Storage"),
    (b'\xd0\x0d\xfe\xed', "Device Tree Blob (DTB / FDT)", "Hardware Device Tree"),
    (b'\xfd7zXZ\x00', "XZ Compressed Archive", "High Compression Payload"),
    (b'\x5d\x00\x00\x80\x00', "LZMA Raw Compressed Block", "Compressed Kernel / FS")
]

def scan_firmware(data: bytes):
    carved_artifacts = []
    data_len = len(data)

    for magic, name, category in FIRMWARE_SIGNATURES:
        pos = 0
        while pos < data_len:
            idx = data.find(magic, pos)
            if idx == -1:
                break
            carved_artifacts.append({
                "offset": hex(idx),
                "decimal_offset": idx,
                "name": name,
                "category": category,
                "magic_hex": magic.hex()
            })
            pos = idx + len(magic)
            if len(carved_artifacts) >= 50:
                break

    return sorted(carved_artifacts, key=lambda x: x["decimal_offset"])
