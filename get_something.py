import struct
import os
import sys


def parse_elf_header(file):
    raw_data = file.read()

    data = struct.unpack_from("16sHHIQQQIHHHHHH", raw_data, 0)

    print('Raw ELF header: ')
    print(data)

    # Разрядность
    print("\nРазрадность: ")
    if data[0][4] == 0x1:
        print("ELF32")
    if data[0][4] == 0x2:
        print("ELF64")
    else:
        print("Weird magic")

    # тип
    print("Type: ", {
        0x0: "None type",
        0x1: "Relocatable file",
        0x2: "Executable file",
        0x3: "Shared object file",
        0x4: "Core file",
        # 5:" Relocatable file",
        0xff00: "Processor-specific (see elf.h)",
        0xffff: "Processor-specific (see elf.h)"
    }.get(data[1], "N/A"))

    print("Entry adress: ", hex(data[4]))

    print("Segment table offset: ", data[5])

    print("Section table offset: ", data[6])


def parse_macho_header(file):
    buffer = file.read()
    res = struct.unpack_from("IiiIIII", buffer)
    print("Raw Mach-O header:")
    print(res)
    print("File type: " + {
        0x1: "relocatable object file",
        0x2: "demand paged executable file",
        0x3: "fixed VM shared library file ",
        0x4: "core file",
        0x5: "preloaded executable file",
        0x6: "dynamically bound shared library",
        0x7: "dynamic link editor",
        0x8: "dynamically bound bundle file",
        0x9: "shared library stub for static",
        0xa: "companion file with only debug",
        0xb: "x86_64 kexts",
    }.get(res[3]))
    print("Bitness: " + {
        0xfeedfacf: "x64",
        0xfeedface: "x32",
        0xcefaedfe: "weird magic, see loader.h @ opensource.apple.com",
        0xcffaedfe: "weird magic, see loader.h @ opensource.apple.com",
    }.get(res[0]))
    print("Number of load commands: " + str(res[4]))
    print("Flags (for more info see loader.h @ opensource.apple.com): " + str(hex(res[6])))


def parse_elf_sections(file):
    buffer = file.read()
    elf_header = struct.unpack_from("16sHHIQQQIHHHHHH", buffer)

    section_header = struct.unpack_from("IIQQQQIIQQ", buffer, elf_header[6] + elf_header[13] * elf_header[11])
    name_table_offset = section_header[4]

    print("Address", "Offset")
    print('{:^3}{:^20}{:^20}{:^30}{:^30}'.format('№', 'Name', 'Type', 'Address', 'Offset'))
    for i in range(0, elf_header[12]):
        section_header = struct.unpack_from("@IIQQQQIIQQ", buffer, elf_header[6] + i * elf_header[11])
        offset = section_header[0] + name_table_offset
        print('{:^3}{:^20}{:^20}{:^30}{:^30}'.format(i, str(buffer[offset:offset + 16]),
                                                     {
                                                         0x0: 'SHT_NULL',
                                                         0x1: 'SHT_PROGBITS',
                                                         0x2: 'SHT_SYMTAB',
                                                         0x3: 'SHT_STRTAB',
                                                         0x4: 'SHT_RELA',
                                                         0x5: 'SHT_HASH',
                                                         0x6: 'SHT_DYNAMIC',
                                                         0x7: 'SHT_NOTE',
                                                         0x8: 'SHT_NOBITS',
                                                         0x9: 'SHT_REL',
                                                         0x0A: 'SHT_SHLIB',
                                                         0x0B: 'SHT_DYNSYM',
                                                         0x0E: 'SHT_INIT_ARRAY',
                                                         0x0F: 'SHT_FINI_ARRAY',
                                                         0x10: 'SHT_PREINIT_ARRAY',
                                                         0x11: 'SHT_GROUP',
                                                         0x12: 'SHT_SYMTAB_SHNDX',
                                                         0x13: 'SHT_NUM',
                                                         0x7fffffff: 'SHT_HIPROC',
                                                         0xffffffff: 'SHT_HIUSER',
                                                         0x70000000: 'SHT_LOPROC',
                                                         0x80000000: 'SHT_LOUSER',
                                                         0x6ffffffd: 'SHT_GNU_verdef',
                                                         0x6ffffffe: 'SHT_GNU_verneed',
                                                         0x6fffffff: 'SHT_GNU_versym',
                                                         0x6ffffff6: 'SHT_GNU_HASH'
                                                     }.get(section_header[1],
                                                           'UNKNOWN TYPE: {}'.format(hex(section_header[1]))),
                                                     hex(section_header[3]),
                                                     hex(section_header[4])))


def parse_macho_sections(file):
    buffer = file.read()
    res = struct.unpack_from("IiiIIII", buffer)
    print(res)
    if res[0] == 0xfeedfacf:
        offset = 8 * 4 + res[5]
        offset = (offset // 4096 + 1) * 4096
        segment = struct.unpack_from("II16s", buffer[offset:])
        print(segment)

    if res[0] == 0xfeedface:
        offset = 7 * 4 + res[5]


def parse_pe_header(file):
    pass


def parse_pe_sections(file):
    pass


if __name__ == "__main__":
    file_name = sys.argv[1]  # file name
    mode = int(sys.argv[2])  # task number

    infile = open(file_name, "rb")
    result = "error"

    if mode == 1:
        parse_elf_header(infile)
    if mode == 3:
        parse_elf_sections(infile)
    if mode == 5:
        parse_macho_header(infile)
    if mode == 7:
        parse_macho_sections(infile)
    if mode == 9:
        parse_pe_header(infile)
    if mode == 10:
        parse_pe_sections(infile)
