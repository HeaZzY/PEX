# PEX Parser

A lightweight Portable Executable (PE) file analyzer written in C for Windows executables and DLLs.

## Features

- **DOS Header Analysis** - Magic signature, stub size, PE offset
- **NT Headers Parsing** - File header, optional header, and data directories
- **Section Analysis** - Memory layout, permissions (R/W/X), and characteristics
- **Architecture Detection** - x86, x64, ARM support
- **Security Features** - ASLR, DEP, CFG detection
- **Clean ASCII Output** - Professional formatting with tables

## Usage

```bash
PEX.exe <file.exe>
```

### Example
```bash
PEX.exe notepad.exe
```

## Output

The parser displays detailed information about:
- File metadata and size
- DOS header structure
- NT headers and file characteristics
- Optional header with entry points and alignments
- Data directories (imports, exports, resources, etc.)
- Section table with permissions and memory layout
- Security mitigations enabled

## Sample Output

```
================================================================================
                               PEX
================================================================================
File: notepad.exe
Size: 2048512 bytes

DOS HEADER:
  Magic Number (e_magic)          : 0x5A4D
  PE Header Offset (e_lfanew)     : 0x000000F8

SECTIONS:
+-------------+----------+----------+----------+----------+-------------+
|    Name     | VirtAddr | VirtSize | RawAddr  | RawSize  | Permissions |
+-------------+----------+----------+----------+----------+-------------+
| .text       | 00001000 | 0000A47F | 00000400 | 0000A600 | R-X         |
| .rdata      | 0001C000 | 0000579E | 0000AA00 | 00005800 | R--         |
| .data       | 00022000 | 00000960 | 00010200 | 00000200 | RW-         |
+-------------+----------+----------+----------+----------+-------------+
```

## Build

Use Visual Studio:
```bash
cl PEparser.c
```

## Requirements

- Windows OS
- C compiler with Windows SDK
- Target PE files (EXE, DLL, SYS)
