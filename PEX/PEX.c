#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


void getPermissionsString(DWORD characteristics, char* permissions) {
    permissions[0] = (characteristics & 0x20000000) ? 'R' : '-';
    permissions[1] = (characteristics & 0x80000000) ? 'W' : '-';
    permissions[2] = (characteristics & 0x20000000) ? 'X' : '-';
    permissions[3] = '\0';

    if (characteristics & 0x20000000) {
        permissions[2] = 'X';
    }
    if (characteristics & 0x00000020) {
        permissions[2] = 'X';
    }
}

BOOL extractImgDosHeader(LPVOID pPE, PIMAGE_DOS_HEADER* pImgDosHdr) {
    *pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;
    if ((*pImgDosHdr)->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    return TRUE;
}

BOOL extractNTHeader(LPVOID pPE, PIMAGE_DOS_HEADER pImgDosHdr, PIMAGE_NT_HEADERS* pImgNtHdrs) {
    *pImgNtHdrs = (PIMAGE_NT_HEADERS)((BYTE*)pPE + pImgDosHdr->e_lfanew);
    if ((*pImgNtHdrs)->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    return TRUE;
}

BOOL extractFileHeader(PIMAGE_NT_HEADERS pImgNtHdrs, IMAGE_FILE_HEADER* ImgFileHdr) {
    *ImgFileHdr = pImgNtHdrs->FileHeader;
    return TRUE;
}

BOOL extractOptionalHeader(PIMAGE_NT_HEADERS pImgNtHdrs, IMAGE_OPTIONAL_HEADER* ImgOptHdr) {
    *ImgOptHdr = pImgNtHdrs->OptionalHeader;
    if ((*ImgOptHdr).Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        return FALSE;
    }
    return TRUE;
}


LPVOID LoadPEFromDisk(const char* szFilePath, PDWORD pdwFileSize) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    LPVOID pFileBuffer = NULL;
    DWORD dwFileSize = 0;
    DWORD dwBytesRead = 0;

    // Ouvrir le fichier
    hFile = CreateFileA(
        szFilePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Erreur: Impossible d'ouvrir le fichier\n");
        return NULL;
    }

    // Récupérer la taille
    dwFileSize = GetFileSize(hFile, NULL);
    if (dwFileSize == INVALID_FILE_SIZE) {
        printf("[-] Erreur: Impossible de récupérer la taille\n");
        CloseHandle(hFile);
        return NULL;
    }

    // Allouer le buffer
    pFileBuffer = malloc(dwFileSize);
    if (!pFileBuffer) {
        printf("[-] Erreur: Allocation mémoire échouée\n");
        CloseHandle(hFile);
        return NULL;
    }

    // Lire le fichier
    if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwBytesRead, NULL) ||
        dwBytesRead != dwFileSize) {
        printf("[-] Erreur: Lecture échouée\n");
        free(pFileBuffer);
        CloseHandle(hFile);
        return NULL;
    }

    CloseHandle(hFile);

    if (pdwFileSize) {
        *pdwFileSize = dwFileSize;
    }

    printf("[+] File loaded: %lu bytes\n", dwFileSize);
    return pFileBuffer;
}


void printPEInformation(LPVOID pPE, PIMAGE_DOS_HEADER pImgDosHdr, PIMAGE_NT_HEADERS pImgNtHdrs, IMAGE_FILE_HEADER ImgFileHdr, IMAGE_OPTIONAL_HEADER ImgOptHdr, DWORD dwFileSize, PVOID fileName) {

    printf("================================================================================\n\t\t\t\tPE ANALYZER\n================================================================================\n");
    printf("File: %s\nSize: %d bytes\n", fileName, dwFileSize);
    printf("================================================================================\n\t\t\t\tDOS HEADER\n================================================================================\n");
    printf("  Magic Number (e_magic)          : 0x%04X\n", pImgDosHdr->e_magic);
    printf("  Bytes on Last Page (e_cblp)     : %u\n", pImgDosHdr->e_cblp);
    printf("  Pages in File (e_cp)            : %u\n", pImgDosHdr->e_cp);
    printf("  Relocations (e_crlc)            : %u\n", pImgDosHdr->e_crlc);
    printf("  Header Size in Paragraphs       : %u\n", pImgDosHdr->e_cparhdr);
    printf("  Min Extra Paragraphs (e_minalloc): %u\n", pImgDosHdr->e_minalloc);
    printf("  Max Extra Paragraphs (e_maxalloc): %u\n", pImgDosHdr->e_maxalloc);
    printf("  Initial Stack Segment (e_ss)    : 0x%04X\n", pImgDosHdr->e_ss);
    printf("  Initial Stack Pointer (e_sp)    : 0x%04X\n", pImgDosHdr->e_sp);
    printf("  Checksum (e_csum)               : 0x%04X\n", pImgDosHdr->e_csum);
    printf("  Initial IP (e_ip)               : 0x%04X\n", pImgDosHdr->e_ip);
    printf("  Initial Code Segment (e_cs)     : 0x%04X\n", pImgDosHdr->e_cs);
    printf("  Relocation Table Offset         : 0x%04X\n", pImgDosHdr->e_lfarlc);
    printf("  Overlay Number (e_ovno)         : %u\n", pImgDosHdr->e_ovno);
    printf("  OEM Identifier (e_oemid)        : 0x%04X\n", pImgDosHdr->e_oemid);
    printf("  OEM Information (e_oeminfo)     : 0x%04X\n", pImgDosHdr->e_oeminfo);
    printf("  PE Header Offset (e_lfanew)     : 0x%08lX (%lu)\n", pImgDosHdr->e_lfanew, pImgDosHdr->e_lfanew);

    // NT Headers
    printf("================================================================================\n\t\t\t\tNT HEADERS\n================================================================================\n");
    printf("  File header at                  : %p\n", pImgNtHdrs->FileHeader);
    printf("  Optional header at                  : %p\n", pImgNtHdrs->OptionalHeader);



    // Calcul DOS stub
    DWORD dosStubSize = pImgDosHdr->e_lfanew - sizeof(IMAGE_DOS_HEADER);
    printf("  DOS Stub Size                   : %lu bytes\n", dosStubSize);

    printf("\n");



    printf("================================================================================\n\t\t\t\tFILE HEADERS\n================================================================================\n");
    printf("    Machine Type                  : ");
    switch (ImgFileHdr.Machine) {
    case IMAGE_FILE_MACHINE_I386:
        printf("IMAGE_FILE_MACHINE_I386 (0x%04X) - x86\n", ImgFileHdr.Machine);
        break;
    case IMAGE_FILE_MACHINE_AMD64:
        printf("IMAGE_FILE_MACHINE_AMD64 (0x%04X) - x64\n", ImgFileHdr.Machine);
        break;
    case IMAGE_FILE_MACHINE_ARM:
        printf("IMAGE_FILE_MACHINE_ARM (0x%04X) - ARM\n", ImgFileHdr.Machine);
        break;
    case IMAGE_FILE_MACHINE_ARM64:
        printf("IMAGE_FILE_MACHINE_ARM64 (0x%04X) - ARM64\n", ImgFileHdr.Machine);
        break;
    default:
        printf("Unknown (0x%04X)\n", ImgFileHdr.Machine);
        break;
    }

    printf("    Number of Sections            : %u\n", ImgFileHdr.NumberOfSections);

    printf("    Time Date Stamp               : 0x%08lX", ImgFileHdr.TimeDateStamp);
    if (ImgFileHdr.TimeDateStamp != 0) {
        time_t timestamp = (time_t)ImgFileHdr.TimeDateStamp;
        char* timeStr = ctime(&timestamp);
        if (timeStr) {
            timeStr[strlen(timeStr) - 1] = '\0';
            printf(" (%s)", timeStr);
        }
    }
    printf("\n");

    printf("    Pointer to Symbol Table       : 0x%08lX", ImgFileHdr.PointerToSymbolTable);
    if (ImgFileHdr.PointerToSymbolTable == 0) {
        printf(" (No symbols)");
    }
    printf("\n");

    printf("    Number of Symbols             : %lu\n", ImgFileHdr.NumberOfSymbols);
    printf("    Size of Optional Header       : %u bytes\n", ImgFileHdr.SizeOfOptionalHeader);

    printf("    Characteristics               : 0x%04X\n", ImgFileHdr.Characteristics);
    if (ImgFileHdr.Characteristics & 0x0001)
        printf("      - IMAGE_FILE_RELOCS_STRIPPED\n");
    if (ImgFileHdr.Characteristics & 0x0002)
        printf("      - IMAGE_FILE_EXECUTABLE_IMAGE\n");
    if (ImgFileHdr.Characteristics & 0x0004)
        printf("      - IMAGE_FILE_LINE_NUMBERS_STRIPPED\n");
    if (ImgFileHdr.Characteristics & 0x0008)
        printf("      - IMAGE_FILE_LOCAL_SYMS_STRIPPED\n");
    if (ImgFileHdr.Characteristics & 0x0020)
        printf("      - IMAGE_FILE_LARGE_ADDRESS_AWARE\n");
    if (ImgFileHdr.Characteristics & 0x0100)
        printf("      - IMAGE_FILE_32BIT_MACHINE\n");
    if (ImgFileHdr.Characteristics & 0x0200)
        printf("      - IMAGE_FILE_DEBUG_STRIPPED\n");
    if (ImgFileHdr.Characteristics & 0x1000)
        printf("      - IMAGE_FILE_SYSTEM\n");
    if (ImgFileHdr.Characteristics & 0x2000)
        printf("      - IMAGE_FILE_DLL\n");



    printf("================================================================================\n\t\t\t\tOPTIONAL HEADERS\n================================================================================\n");
    printf("    Magic                         : ");
    switch (ImgOptHdr.Magic) {
    case 0x010B:  // IMAGE_NT_OPTIONAL_HDR32_MAGIC
        printf("PE32 (0x%04X) - 32-bit\n", ImgOptHdr.Magic);
        break;
    case 0x020B:  // IMAGE_NT_OPTIONAL_HDR64_MAGIC
        printf("PE32+ (0x%04X) - 64-bit\n", ImgOptHdr.Magic);
        break;
    case 0x0107:  // IMAGE_ROM_OPTIONAL_HDR_MAGIC
        printf("ROM (0x%04X) - ROM image\n", ImgOptHdr.Magic);
        break;
    default:
        printf("Unknown (0x%04X)\n", ImgOptHdr.Magic);
        break;
    }

    printf("    Linker Version                : %u.%u\n",
        ImgOptHdr.MajorLinkerVersion, ImgOptHdr.MinorLinkerVersion);

    printf("    Size of Code                  : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfCode, ImgOptHdr.SizeOfCode);

    printf("    Size of Initialized Data      : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfInitializedData, ImgOptHdr.SizeOfInitializedData);

    printf("    Size of Uninitialized Data    : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfUninitializedData, ImgOptHdr.SizeOfUninitializedData);

    printf("    Entry Point                   : 0x%08lX (RVA)\n", ImgOptHdr.AddressOfEntryPoint);
    printf("    Base of Code                  : 0x%08lX (RVA)\n", ImgOptHdr.BaseOfCode);



    printf("    Image Base                    : 0x%08lX\n", ImgOptHdr.ImageBase);
    printf("    Section Alignment             : 0x%08lX (%lu)\n",
        ImgOptHdr.SectionAlignment, ImgOptHdr.SectionAlignment);
    printf("    File Alignment                : 0x%08lX (%lu)\n",
        ImgOptHdr.FileAlignment, ImgOptHdr.FileAlignment);

    printf("    OS Version (Required)         : %u.%u\n",
        ImgOptHdr.MajorOperatingSystemVersion, ImgOptHdr.MinorOperatingSystemVersion);
    printf("    Image Version                 : %u.%u\n",
        ImgOptHdr.MajorImageVersion, ImgOptHdr.MinorImageVersion);
    printf("    Subsystem Version             : %u.%u\n",
        ImgOptHdr.MajorSubsystemVersion, ImgOptHdr.MinorSubsystemVersion);

    printf("    Win32 Version Value           : 0x%08lX\n", ImgOptHdr.Win32VersionValue);
    printf("    Size of Image                 : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfImage, ImgOptHdr.SizeOfImage);
    printf("    Size of Headers               : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfHeaders, ImgOptHdr.SizeOfHeaders);

    printf("    Checksum                      : 0x%08lX", ImgOptHdr.CheckSum);
    if (ImgOptHdr.CheckSum == 0) {
        printf(" (Not set)");
    }
    printf("\n");

    printf("    Subsystem                     : ");
    switch (ImgOptHdr.Subsystem) {
    case 1:
        printf("IMAGE_SUBSYSTEM_NATIVE (%u) - Native\n", ImgOptHdr.Subsystem);
        break;
    case 2:
        printf("IMAGE_SUBSYSTEM_WINDOWS_GUI (%u) - Windows GUI\n", ImgOptHdr.Subsystem);
        break;
    case 3:
        printf("IMAGE_SUBSYSTEM_WINDOWS_CUI (%u) - Console\n", ImgOptHdr.Subsystem);
        break;
    case 7:
        printf("IMAGE_SUBSYSTEM_POSIX_CUI (%u) - POSIX\n", ImgOptHdr.Subsystem);
        break;
    case 9:
        printf("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI (%u) - Windows CE\n", ImgOptHdr.Subsystem);
        break;
    case 10:
        printf("IMAGE_SUBSYSTEM_EFI_APPLICATION (%u) - EFI App\n", ImgOptHdr.Subsystem);
        break;
    case 11:
        printf("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER (%u) - EFI Driver\n", ImgOptHdr.Subsystem);
        break;
    case 12:
        printf("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER (%u) - EFI Runtime\n", ImgOptHdr.Subsystem);
        break;
    default:
        printf("Unknown (%u)\n", ImgOptHdr.Subsystem);
        break;
    }

    printf("    DLL Characteristics           : 0x%04X\n", ImgOptHdr.DllCharacteristics);
    if (ImgOptHdr.DllCharacteristics & 0x0020)
        printf("      - IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA\n");
    if (ImgOptHdr.DllCharacteristics & 0x0040)
        printf("      - IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE\n");
    if (ImgOptHdr.DllCharacteristics & 0x0080)
        printf("      - IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY\n");
    if (ImgOptHdr.DllCharacteristics & 0x0100)
        printf("      - IMAGE_DLLCHARACTERISTICS_NX_COMPAT\n");
    if (ImgOptHdr.DllCharacteristics & 0x0200)
        printf("      - IMAGE_DLLCHARACTERISTICS_NO_ISOLATION\n");
    if (ImgOptHdr.DllCharacteristics & 0x0400)
        printf("      - IMAGE_DLLCHARACTERISTICS_NO_SEH\n");
    if (ImgOptHdr.DllCharacteristics & 0x0800)
        printf("      - IMAGE_DLLCHARACTERISTICS_NO_BIND\n");
    if (ImgOptHdr.DllCharacteristics & 0x1000)
        printf("      - IMAGE_DLLCHARACTERISTICS_APPCONTAINER\n");
    if (ImgOptHdr.DllCharacteristics & 0x2000)
        printf("      - IMAGE_DLLCHARACTERISTICS_WDM_DRIVER\n");
    if (ImgOptHdr.DllCharacteristics & 0x4000)
        printf("      - IMAGE_DLLCHARACTERISTICS_GUARD_CF\n");
    if (ImgOptHdr.DllCharacteristics & 0x8000)
        printf("      - IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE\n");

    printf("    Stack Reserve Size            : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfStackReserve, ImgOptHdr.SizeOfStackReserve);
    printf("    Stack Commit Size             : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfStackCommit, ImgOptHdr.SizeOfStackCommit);
    printf("    Heap Reserve Size             : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfHeapReserve, ImgOptHdr.SizeOfHeapReserve);
    printf("    Heap Commit Size              : 0x%08lX (%lu bytes)\n",
        ImgOptHdr.SizeOfHeapCommit, ImgOptHdr.SizeOfHeapCommit);

    printf("    Loader Flags                  : 0x%08lX\n", ImgOptHdr.LoaderFlags);
    printf("    Number of RVA and Sizes       : %lu\n", ImgOptHdr.NumberOfRvaAndSizes);

    printf("\n    DATA DIRECTORIES:\n");
    const char* dataDirectoryNames[16] = {
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug Directory",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "COM+ Runtime Header",
        "Reserved"
    };

    for (int i = 0; i < 16 && i < (int)ImgOptHdr.NumberOfRvaAndSizes; i++) {
        printf("    [%2d] %-25s : RVA=0x%08lX, Size=%lu bytes\n",
            i,
            dataDirectoryNames[i],
            ImgOptHdr.DataDirectory[i].VirtualAddress,
            ImgOptHdr.DataDirectory[i].Size);
    }
    printf("\n");


    printf("================================================================================\n\t\t\t\tSECTIONS\n================================================================================\n");

    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

    printf("+-------------+----------+----------+----------+----------+-------------+-------------+\n");
    printf("|    Name     | VirtAddr | VirtSize | RawAddr  | RawSize  | Permissions | Characteristics |\n");
    printf("+-------------+----------+----------+----------+----------+-------------+-------------+\n");

    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        char permissions[4];
        getPermissionsString(pSectionHeader[i].Characteristics, permissions);

        printf("| %-11s | %08lX | %08lX | %08lX | %08lX | %-11s | 0x%08lX  |\n",
            sectionName,
            pSectionHeader[i].VirtualAddress,
            pSectionHeader[i].Misc.VirtualSize,
            pSectionHeader[i].PointerToRawData,
            pSectionHeader[i].SizeOfRawData,
            permissions,
            pSectionHeader[i].Characteristics);
    }

    printf("+-------------+----------+----------+----------+----------+-------------+-------------+\n");


    printf("\nSection Details:\n");
    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, pSectionHeader[i].Name, 8);

        printf("  * %-8s : ", sectionName);

        if (strcmp(sectionName, ".text") == 0) {
            printf("Executable code section");
        }
        else if (strcmp(sectionName, ".rdata") == 0) {
            printf("Read-only data (strings, constants)");
        }
        else if (strcmp(sectionName, ".data") == 0) {
            printf("Initialized read-write data");
        }
        else if (strcmp(sectionName, ".bss") == 0) {
            printf("Uninitialized data");
        }
        else if (strcmp(sectionName, ".pdata") == 0) {
            printf("Exception handling data (x64 only)");
        }
        else if (strcmp(sectionName, ".rsrc") == 0) {
            printf("Resources (icons, dialogs, etc.)");
        }
        else if (strcmp(sectionName, ".reloc") == 0) {
            printf("Base relocation table");
        }
        else if (strcmp(sectionName, ".idata") == 0) {
            printf("Import data");
        }
        else if (strcmp(sectionName, ".edata") == 0) {
            printf("Export data");
        }
        else if (strcmp(sectionName, ".tls") == 0) {
            printf("Thread-local storage");
        }
        else {
            printf("Custom section");
        }

        if (pSectionHeader[i].Characteristics & 0x00000020) {  // IMAGE_SCN_CNT_CODE
            printf(" [CODE]");
        }
        if (pSectionHeader[i].Characteristics & 0x00000040) {  // IMAGE_SCN_CNT_INITIALIZED_DATA
            printf(" [INIT_DATA]");
        }
        if (pSectionHeader[i].Characteristics & 0x00000080) {  // IMAGE_SCN_CNT_UNINITIALIZED_DATA
            printf(" [UNINIT_DATA]");
        }
        if (pSectionHeader[i].Characteristics & 0x02000000) {  // IMAGE_SCN_MEM_DISCARDABLE
            printf(" [DISCARDABLE]");
        }
        if (pSectionHeader[i].Characteristics & 0x10000000) {  // IMAGE_SCN_MEM_SHARED
            printf(" [SHARED]");
        }

        printf("\n");
    }

    printf("\nSection Statistics:\n");
    printf("  Total sections: %u\n", ImgFileHdr.NumberOfSections);

    int executableSections = 0;
    int writableSections = 0;
    DWORD totalVirtualSize = 0;

    for (int i = 0; i < ImgFileHdr.NumberOfSections; i++) {
        if (pSectionHeader[i].Characteristics & 0x20000000) {  // IMAGE_SCN_MEM_EXECUTE
            executableSections++;
        }
        if (pSectionHeader[i].Characteristics & 0x80000000) {  // IMAGE_SCN_MEM_WRITE
            writableSections++;
        }
        totalVirtualSize += pSectionHeader[i].Misc.VirtualSize;
    }

    printf("  Executable sections: %d\n", executableSections);
    printf("  Writable sections: %d\n", writableSections);
    printf("  Total virtual size: 0x%08lX (%lu bytes)\n", totalVirtualSize, totalVirtualSize);

}


int main(int argc, char* argv[]) {
    LPVOID pPE = NULL;
    DWORD dwFileSize = 0;
    PIMAGE_DOS_HEADER pImgDosHdr = NULL;
    PIMAGE_NT_HEADERS pImgNtHdrs = NULL;
    IMAGE_FILE_HEADER ImgFileHdr;
    IMAGE_OPTIONAL_HEADER ImgOptHdr;
    const char* fileName = argv[1];
    if (argc != 2) {
        printf("Usage: %s <file.exe>\n", argv[0]);
        return 1;
    }

    // load PE from the disk
    pPE = LoadPEFromDisk(argv[1], &dwFileSize);
    if (!pPE) {
        printf("[-] PE loading failed\n");
        return 1;
    }

    // extract DOS header
    if (!extractImgDosHeader(pPE, &pImgDosHdr)) {
        printf("[-] Error extracting DOS header");
        return 1;
    }

    // extract NT header
    if (!extractNTHeader(pPE, pImgDosHdr, &pImgNtHdrs)) {
        printf("[-] error extracting NT headers\n");
        return 1;
    }

    // extract File Headers
    if (!extractFileHeader(pImgNtHdrs, &ImgFileHdr)) {
        printf("[-] error extracting file header");
        return 1;
    }

    // extract optional header
    if (!extractOptionalHeader(pImgNtHdrs, &ImgOptHdr)) {
        printf("[-] error extracting optional header");
        return 1;
    }

    // parsing there
    printPEInformation(pPE, pImgDosHdr, pImgNtHdrs, ImgFileHdr, ImgOptHdr, dwFileSize, fileName);


    free(pPE);
    return 0;
}