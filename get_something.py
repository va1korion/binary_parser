import struct
import sys

elfFlag = 0
machoFlag = 0
peFlag = 0

if len(sys.argv) == 0:
    exit()
elif len(sys.argv) == 1:
    exit()
elif len(sys.argv) == 2:
    fileName = sys.argv[1]
    file = open(fileName, 'rb')
    fileData = file.read()
    magicNum = struct.unpack('2B', fileData[0:2])
    if magicNum[0] == 0x4d and magicNum[1] == 0x5a:
        peFlag = 1
        pe = fileName
    if magicNum[0] == 0x7f and magicNum[1] == 0x45:
        elfFlag = 1
        elf = fileName
    if magicNum[0] == 0xcf and magicNum[1] == 0xfa:
        machoFlag = 1
        macho = fileName
else:
    exit()

if elfFlag:
    elfFile = open(elf, 'rb')
    elfData = elfFile.read()
    # PARSING HEADER
    print('----------HEADER----------')

    elfHeaderTemplate = '16B2HI3QI6H'
    elfHeader = struct.unpack(elfHeaderTemplate, elfData[0:64])
    elfMagicNumber = elfHeader[0:16]
    elfObjFileType = elfHeader[16]
    elfArchitecture = elfHeader[17]
    elfVersion = elfHeader[18]
    elfEntryPoint = elfHeader[19]
    elfProgramOffset = elfHeader[20]
    elfSectionOffset = elfHeader[21]
    elfProcFlags = elfHeader[22]
    elfHeaderSize = elfHeader[23]
    elfProgramHeaderTableEntrySize = elfHeader[24]
    elfProgramHeaderTableEntryCount = elfHeader[25]
    elfSectionHeaderTableEntrySize = elfHeader[26]
    elfSectionHeaderTableEntryCount = elfHeader[27]
    elfSectionHeaderStringTableIndex = elfHeader[28]
    STDelfMagicNumber = (0x7F, 0x45, 0x4C, 0x46)

    if elfMagicNumber[0:4] != STDelfMagicNumber:
        print('ERROR: File is not ELF')
        exit()
    else:
        print('File type: ELF')

    if elfObjFileType == 0:
        print('File type: undefined')
    elif elfObjFileType == 1:
        print('File type: lib')
    elif elfObjFileType == 2:
        print('File type: exec')
    elif elfObjFileType == 3:
        print('File type: dll')

    if hex(elfArchitecture) == 0x3E:
        print('Archutecture: ', elfArchitecture, '(AMD x86-64)')
    elif hex(elfArchitecture) == 0x28:
        print('Archutecture: ', elfArchitecture, '(ARM)')
    elif hex(elfArchitecture) == 0xAF:
        print('Archutecture: ', elfArchitecture, '(ELBRUS)')
    print('Entry point: ', hex(elfEntryPoint), sep='')
    print('Segment offset: ', hex(elfProgramOffset), sep='')
    print('Segment count: ', elfProgramHeaderTableEntryCount)
    print('Section offset: ', hex(elfSectionOffset), sep='')
    print('Section count: ', elfSectionHeaderTableEntryCount)
    print('--------------------------')
    print()
    print()

    print('---------SECTIONS---------')

    if elfSectionOffset == 0:
        print('There are not any sections in file')
        exit()

    elfSectionTemplate = '2I4Q2I2Q'
    pointer = elfSectionOffset
    size = elfSectionHeaderTableEntrySize
    print("%4s%20s%20s%20s%20s" % (
        '[x]', 'Section name', 'Section type', 'Section offset', 'Section addr'))
    types = ['NULL', 'PROGBITS', 'SYMTAB', 'STRTAB', 'RELA', 'HASH', 'DYNAMIC', 'NOTE', 'NOBITS', 'REL', 'SHLIB', 'DYNSYM',
             'INIT_ARRAY', 'FINI_ARRAY', 'PREINIT_ARRA', 'GROUP', 'SYMTAB_SHNDX', 'LOOS', 'HIOS', 'LOPROC', 'HIPROC', 'LOUSER', 'HIUSER']
    namesSectPointer = pointer + size * (elfSectionHeaderTableEntryCount - 1)
    section = struct.unpack(
        elfSectionTemplate, elfData[namesSectPointer:namesSectPointer + size])
    sectionName = section[0]
    sectionType = section[1]
    sectionFlags = section[2]
    sectionAddr = section[3]
    sectionOffset = section[4]
    sectionSize = section[5]
    sectionLink = section[6]
    sectionInfo = section[7]
    sectionAllign = section[8]
    sectionEntrySize = section[9]

    templ = sectionSize * 'c'
    stra = struct.unpack(
        templ, elfData[sectionOffset:sectionOffset + sectionSize])
    names = ''
    for i in range(len(stra)):
        if stra[i] == b"\x00":
            names += "$"
        else:
            names += stra[i].decode('utf-8', 'backslashreplace')
    for i in range(elfSectionHeaderTableEntryCount):
        section = struct.unpack(
            elfSectionTemplate, elfData[pointer:pointer + size])
        sectionName = section[0]
        sectionType = section[1]
        sectionFlags = section[2]
        sectionAddr = section[3]
        sectionOffset = section[4]
        sectionSize = section[5]
        sectionLink = section[6]
        sectionInfo = section[7]
        sectionAllign = section[8]
        sectionEntrySize = section[9]
        pointer += size
        if sectionType > len(types):
            type = 'LOOS'
        else:
            type = types[sectionType]
        name = ''
        k = sectionName
        while names[k] != '$':
            name += names[k]
            k += 1
        print("[%2d]%20s%20s%20s%20s" %
              (i, name, type, hex(sectionOffset), hex(sectionAddr)))

    print('--------------------------')
    print()
    print()


if machoFlag:

    print('----------HEADER----------')
    machoFile = open(macho, 'rb')
    machoData = machoFile.read()

    machoHeaderTemplate = '<L2I4L'
    STDmachoMagicNumber = 0xFEEDFACF
    machoHeader = struct.unpack(machoHeaderTemplate, machoData[0:28])

    machoMagicNumber = machoHeader[0]

    if machoMagicNumber == 0xFEEDFACF:
        print('File type: Mach-O')
        print('Architecture: x64')
        currentPoint = 32
    elif machoMagicNumber == 0xFEEDFACE:
        print('File type: Mach-O')
        print('Architecture: x32')
        currentPoint = 28
    else:
        print('ERROR: File is not Mach-O')

    machoCPUType = machoHeader[1]
    machoMachine = machoHeader[2]
    machoFileType = machoHeader[3]
    if machoFileType == 0:
        print('File type: undefined')
    elif machoFileType == 1:
        print('File type: lib')
    elif machoFileType == 2:
        print('File type: exec')
    elif machoFileType == 3:
        print('File type: dll')
    machoNumberCommands = machoHeader[4]
    print('Commands number: ', machoNumberCommands)
    machoSizeCommands = machoHeader[5]
    machoFlags = machoHeader[6]
    flags = machoFlags
    print('Flags: ', hex(flags))
    if (flags & (1 << 0)) >> 0 == 1:
        print("\tMH_NOUNDEFS")
    if (flags & (1 << 1)) >> 1 == 1:
        print("\tMH_INCRLINK")
    if (flags & (1 << 2)) >> 2 == 1:
        print("\tMH_DYLDLINK")
    if (flags & (1 << 3)) >> 3 == 1:
        print("\tMH_BINDATLOAD")
    if (flags & (1 << 4)) >> 4 == 1:
        print("\tMH_PREBOUND")
    if (flags & (1 << 5)) >> 5 == 1:
        print("\tMH_SPLIT_SEGS")
    if (flags & (1 << 6)) >> 6 == 1:
        print("\tMH_LAZY_INIT")
    if (flags & (1 << 7)) >> 7 == 1:
        print("\tMH_TWOLEVEL")
    if (flags & (1 << 8)) >> 8 == 1:
        print("\tMH_FORCE_FLAT")
    if (flags & (1 << 9)) >> 9 == 1:
        print("\tMH_NOMULTIDEFS")
    if (flags & (1 << 10)) >> 10 == 1:
        print("\tMH_NOFIXPREBINDING")
    if (flags & (1 << 11)) >> 11 == 1:
        print("\tMH_PREBINDABLE")
    if (flags & (1 << 12)) >> 12 == 1:
        print("\tMH_ALLMODSBOUND")
    if (flags & (1 << 13)) >> 13 == 1:
        print("\tMH_SUBSECTIONS_VIA_SYMBOLS")
    if (flags & (1 << 14)) >> 14 == 1:
        print("\tMH_CANONICAL")
    if (flags & (1 << 15)) >> 15 == 1:
        print("\tMH_WEAK_DEFINES")
    if (flags & (1 << 16)) >> 16 == 1:
        print("\tMH_BINDS_TO_WEAK")
    if (flags & (1 << 17)) >> 17 == 1:
        print("\tMH_ALLOW_STACK_EXECUTION")
    if (flags & (1 << 18)) >> 18 == 1:
        print("\tMH_ROOT_SAFE")
    if (flags & (1 << 19)) >> 19 == 1:
        print("\tMH_SETUID_SAFE")
    if (flags & (1 << 20)) >> 20 == 1:
        print("\tMH_NO_REEXPORTED_DYLIBS")
    if (flags & (1 << 21)) >> 21 == 1:
        print("\tMH_PIE")
    if (flags & (1 << 22)) >> 22 == 1:
        print("\tMH_DEAD_STRIPPABLE_DYLIB")
    if (flags & (1 << 23)) >> 23 == 1:
        print("\tMH_HAS_TLV_DESCRIPTORS")
    if (flags & (1 << 24)) >> 24 == 1:
        print("\tMH_NO_HEAP_EXECUTION")

    print('--------------------------')
    print()
    print()

    print('---------SECTIONS---------')
    machoLoadCommandTemplate = '2I'
    machoSegmentTemplate = '2I16c4Q2i2I'
    machoSectionTemplate = '16c16c2Q8I'
    print("%s%25s%30s%30s" %
          ('Section name', 'Segment name', 'Section offset', 'Section addr'))
    for i in range(machoNumberCommands):
        CurrentLoadCommand = struct.unpack(
            machoLoadCommandTemplate, machoData[currentPoint:currentPoint + 8])
        CurrentLoadCommandType = CurrentLoadCommand[0]
        CurrentLoadCommandSize = CurrentLoadCommand[1]
        if CurrentLoadCommandType == 0x19:
            # That means this is segment (LC_SEGMENT_64)
            CurrentSegment = struct.unpack(
                machoSegmentTemplate, machoData[currentPoint:currentPoint + 72])
            CurrentSegmentCmd = CurrentSegment[0]
            CurrentSegmentSize = CurrentSegment[1]
            CurrentSegmentName = str(CurrentSegment[2:18])
            CurrentSegmentVMAddr = CurrentSegment[18]
            CurrentSegmentVMSize = CurrentSegment[19]
            CurrentSegmentFileOff = CurrentSegment[20]
            CurrentSegmentFileSize = CurrentSegment[21]
            CurrentSegmentMaxProt = CurrentSegment[22]
            CurrentSegmentInitProt = CurrentSegment[23]
            CurrentSegmentNSects = CurrentSegment[24]
            CurrentSegmentFlags = CurrentSegment[25]

            currentPointSects = currentPoint + 72
            for j in range(CurrentSegmentNSects):
                CurrentSection = struct.unpack(
                    machoSectionTemplate, machoData[currentPointSects:currentPointSects + 80])
                CurrentSectionName = CurrentSection[0:16]
                name = ''
                for k in range(16):
                    name += CurrentSectionName[k].decode(
                        'utf-8', 'backslashreplace')
                CurrentSectionSegName = CurrentSection[16:32]
                nameSeg = ''
                for k in range(16):
                    nameSeg += CurrentSectionSegName[k].decode(
                        'utf-8', 'backslashreplace')
                CurrentSectionAddr = CurrentSection[32]
                CurrentSectionSize = CurrentSection[33]
                CurrentSectionOffset = CurrentSection[34]
                CurrentSectionAlign = CurrentSection[35]
                CurrentSectionRelOff = CurrentSection[36]
                CurrentSectionNReloc = CurrentSection[37]
                CurrentSectionFlags = CurrentSection[38]
                CurrentSectionRes1 = CurrentSection[39]
                CurrentSectionRes2 = CurrentSection[40]
                CurrentSectionRes3 = CurrentSection[41]
                print("%16s%35s%30s%30s" % (name, nameSeg, hex(
                    CurrentSectionOffset), hex(CurrentSectionAddr)))
                currentPointSects += 80
        currentPoint += CurrentLoadCommandSize
    print('--------------------------')
    print()
    print()

if peFlag:

    print('----------HEADER----------')
    peFile = open(pe, 'rb')
    peData = peFile.read()

    peHeaderTemplate = '2c13H4H2H10HI'
    peHeader = struct.unpack(peHeaderTemplate, peData[0:64])
    e_magic = (peHeader[0] + peHeader[1]).decode('utf-8', 'backslashreplace')

    if e_magic != 'MZ':
        print("Error: file is not a PE")
        exit()

    e_cblp = peHeader[2]
    e_cp = peHeader[3]
    e_crlc = peHeader[4]
    e_cparhdr = peHeader[5]
    e_minalloc = peHeader[6]
    e_maxalloc = peHeader[7]
    e_ss = peHeader[8]
    e_sp = peHeader[9]
    e_csum = peHeader[10]
    e_ip = peHeader[11]
    e_cs = peHeader[12]
    e_lfarlc = peHeader[13]
    e_ovno = peHeader[14]
    e_res = peHeader[15:19]
    e_oemid = peHeader[19]
    e_oeminfo = peHeader[20]
    e_res2 = peHeader[21:31]
    e_lfanew = peHeader[31]  # PE HEADER OFFSET
    peHeaderPEOffset = e_lfanew

    print('File type: PE (magic num = MZ)')
    peHeaderPETemplate = 'I' + '2H3I2H'
    peHeaderPE = struct.unpack(
        peHeaderPETemplate, peData[peHeaderPEOffset:peHeaderPEOffset + 24])
    Signature = peHeaderPE[0]
    Machine = peHeaderPE[1]
    print('Architecture: ', hex(Machine))
    NumberOfSections = peHeaderPE[2]
    print('Number of sections: ', NumberOfSections)
    TimeDateStamp = peHeaderPE[3]
    import datetime
    dt = datetime.datetime.fromtimestamp(TimeDateStamp)
    print('Creation date:', dt)
    PointerToSymbolTable = peHeaderPE[4]
    NumberOfSymbols = peHeaderPE[5]
    SizeOfOptionalHeader = peHeaderPE[6]
    Characteristics = peHeaderPE[7]
    print('Attributes:')
    if (Characteristics & (1 << 0)) >> 0 == 1:  # 0b1 0x1
        print("\tIMAGE_FILE_RELOCS_STRIPPED")
    if (Characteristics & (1 << 1)) >> 1 == 1:  # 0b10 0x2
        print("\tIMAGE_FILE_EXECUTABLE_IMAGE")
    if (Characteristics & (1 << 2)) >> 2 == 1:  # 0b100 0x4
        print("\tIMAGE_FILE_LINE_NUMS_STRIPPED")
    if (Characteristics & (1 << 3)) >> 3 == 1:  # 0b1000 0x8
        print("\tIMAGE_FILE_LOCAL_SYMS_STRIPPED")
    if (Characteristics & (1 << 4)) >> 4 == 1:  # 0b10000 0x10
        print("\tIMAGE_FILE_AGGRESIVE_WS_TRIM")
    if (Characteristics & (1 << 5)) >> 5 == 1:  # 0b100000 0x20
        print("\tIMAGE_FILE_LARGE_ADDRESS_AWARE")
    if (Characteristics & (1 << 6)) >> 6 == 1:  # 0b1000000 0x40
        print("\tIMAGE_FILE_16BIT_MACHINE")
    if (Characteristics & (1 << 7)) >> 7 == 1:  # 0b10000000 0x80
        print("\tIMAGE_FILE_BYTES_REVERSED_LO")
    if (Characteristics & (1 << 8)) >> 8 == 1:  # 0b100000000 0x100
        print("\tIMAGE_FILE_32BIT_MACHINE")
    if (Characteristics & (1 << 9)) >> 9 == 1:  # 0b1000000000 0x200
        print("\tIMAGE_FILE_DEBUG_STRIPPED")
    if (Characteristics & (1 << 10)) >> 10 == 1:  # 0b10000000000 0x400
        print("\tIMAGE_FILE_REMOVABLE_RUN_FROM_SWAP")
    if (Characteristics & (1 << 11)) >> 11 == 1:  # 0b100000000000 0x800
        print("\tIMAGE_FILE_NET_RUN_FROM_SWAP")
    if (Characteristics & (1 << 12)) >> 12 == 1:  # 0b1000000000000 0x1000
        print("\tIMAGE_FILE_SYSTEM ")
    if (Characteristics & (1 << 13)) >> 13 == 1:  # 0b10000000000000 0x2000
        print("\tIMAGE_FILE_DLL")
    if (Characteristics & (1 << 14)) >> 14 == 1:  # 0b100000000000000 0x4000
        print("\tIMAGE_FILE_UP_SYSTEM_ONLY")
    if (Characteristics & (1 << 15)) >> 15 == 1:  # 0b1000000000000000 0x8000
        print("\tIMAGE_FILE_BYTES_REVERSED_HI")

    print('--------------------------')
    print()
    print()
    # print(SizeOfOptionalHeader)
    peOptionHeaderPointer = peHeaderPEOffset + 24
    peOptionHeaderTemplate = 'H2c5IQ2I6H4I2H4Q2I32I'
    peOptionHeader = struct.unpack(
        peOptionHeaderTemplate, peData[peOptionHeaderPointer:peOptionHeaderPointer + SizeOfOptionalHeader])
    # print(peOptionHeader[30:])
    peDataPointer = peHeaderPEOffset + 24 + 112  # + SizeOfOptionalHeader + 11
    peDataTemplate = '2I'
    for i in range(16):
        peDataS = struct.unpack(
            peDataTemplate, peData[peDataPointer:peDataPointer + 8])
        if i == 1:
            peimportVA = peDataS[0]
            peimportSize = peDataS[1]
            # print(peimportVA)
        # if i == 1:
        #     prImportVa = peDataS[0]
        #     peImportSize = peDataS[1]
        peDataPointer += 8

    print('---------SECTIONS---------')
    peSectionTemplate = '8cI5I2HI'
    pePoint = peHeaderPEOffset + 24 + SizeOfOptionalHeader
    print("%4s%20s%20s%20s%20s" % (
        '[ x]', 'Section name', 'Section offset', 'Section addr', 'Section attr'))

    curExpAddr = 0
    importSectionAddr = 0

    for i in range(NumberOfSections):
        peCurrentSection = struct.unpack(
            peSectionTemplate, peData[pePoint:pePoint + 40])
        peCurrentSectionName = peCurrentSection[0:8]
        name = ''
        for k in range(8):
            name += peCurrentSectionName[k].decode('utf-8', 'backslashreplace')
        peCurrentSectionSize = peCurrentSection[8]
        peCurrentSectionAddr = peCurrentSection[9]
        peCurrentSectionSizeRaw = peCurrentSection[10]
        peCurrentSectionPointerRaw = peCurrentSection[11]

        if (peimportVA <= peCurrentSectionAddr) and (peimportVA >= curExpAddr):
            importSectionAddr = curExpAddr
            importSectionRaw = curRaw
        else:
            curExpAddr = peCurrentSectionAddr
            curRaw = peCurrentSectionPointerRaw

        peCurrentSectionPointerRel = peCurrentSection[12]
        peCurrentSectionPointerLin = peCurrentSection[13]
        peCurrentSectionNumberRel = peCurrentSection[14]
        peCurrentSectionNumberLin = peCurrentSection[15]
        peCurrentSectionCharacteristics = peCurrentSection[16]
        pePoint += 40
        print("[%2d]%20s%20s%20s%22s" % (i, name, hex(peCurrentSectionPointerRaw), hex(
            peCurrentSectionAddr), hex(peCurrentSectionCharacteristics)))

    print('--------------------------')
    print()
    print()

    print('---------IMPORTS----------')

    importSectionAddrRAWAddr = peimportVA - importSectionAddr + importSectionRaw
    alph = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._--01234567890'
    libs = []
    for kk in range(int(peimportSize / 20)):
        x = struct.unpack(
            '5I', peData[importSectionAddrRAWAddr:importSectionAddrRAWAddr + 20])
        libRVA = x[3]
        libRAW = libRVA - importSectionAddr + importSectionRaw
        libName = ''
        xk = 1
        while xk == 1:
            y = struct.unpack('c', peData[libRAW:libRAW + 1])
            c = y[0].decode('utf-8', 'backslashreplace')
            if c in alph:
                libName += c
                libRAW += 1
            else:
                libs.append(libName)
                libName = ''
                xk = 0
        importSectionAddrRAWAddr += 20
    for i in range(len(libs) - 1):
        print(libs[i])
    print('--------------------------')