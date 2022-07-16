# genelf

genelf will reconstruct a working executable ELF file from a process image

## Usage
```
$ genelf -h
Usage: genelf [-hv] -p PID [output-file]
       genelf [-hv] -r CORE [output-file]
Options:
  -p  Attach to process with process id PID and generate an ELF executable
  -r  Generate ELF executable from CORE file
  -v  Print verbose output
  -h  Print help message

$ genelf -vp $(pgrep sleep)
[+] Reading process
    Text segment: 0x2000 - 0x62f9 (offset: 0x2000, size: 17145 bytes)
    Data segment: 0x9d30 - 0xa220 (offset: 0x8d30, size: 1264 bytes)
    Dynamic segment: 0x9df8 - 0x9fd8 (size: 480 bytes)
[+] Patching got[5]:
    0xa028	0x300000007	0x2056	__errno_location
[+] Patching got[9]:
    0xa048	0x800000007	0x2096	strtod
[+] Patching got[10]:
    0xa050	0x900000007	0x20a6	textdomain
[+] Patching got[13]:
    0xa068	0xc00000007	0x20d6	bindtextdomain
[+] Patching got[18]:
    0xa090	0x1100000007	0x2126	getopt_long
[+] Patching got[21]:
    0xa0a8	0x1400000007	0x2156	nanosleep
[+] Patching got[22]:
    0xa0b0	0x1500000007	0x2166	strrchr
[+] Patching got[38]:
    0xa130	0x2700000007	0x2266	setlocale
[+] Patching got[42]:
    0xa150	0x2b00000007	0x22a6	__cxa_atexit
[+] Generating .shstrtab
[+] Generating section header table
[+] Writing to file: sleep

$ readelf -SW sleep
There are 26 section headers, starting at offset 0x930b:

Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        00000000000002a8 0002a8 00001c 00   A  0   0  1
  [ 2] .note             NOTE            00000000000002c4 0002c4 000044 00   A  0   0  4
  [ 3] .gnu.hash         GNU_HASH        0000000000000308 000308 00002c 00   A  4   0  8
  [ 4] .dynsym           DYNSYM          0000000000000350 000350 0005a0 18   A  5   1  8
  [ 5] .dynstr           STRTAB          00000000000008f0 0008f0 0002bf 00   A  0   0  8
  [ 6] .gnu.version      VERSYM          0000000000000bb0 000bb0 000078 02   A  4   0  2
  [ 7] .gnu.version_r    VERNEED         0000000000000c28 000c28 000060 00   A  5   1  8
  [ 8] .rela.dyn         RELA            0000000000000c88 000c88 0002b8 18   A  4   0  8
  [ 9] .rela.plt         RELA            0000000000000f40 000f40 000450 18  AI  4  22  8
  [10] .init             PROGBITS        0000000000002000 002000 000020 00  AX  0   0  4
  [11] .plt              PROGBITS        0000000000002020 002020 0002f0 10  AX  0   0 16
  [12] .plt.got          PROGBITS        0000000000002310 002310 000008 08  AX  0   0  8
  [13] .text             PROGBITS        0000000000002320 002320 003fd9 00  AX  0   0 16
  [14] .fini             PROGBITS        00000000000062f0 0062f0 000009 00  AX  0   0  4
  [15] .rodata           PROGBITS        0000000000007000 007000 000b94 00   A  0   0  8
  [16] .eh_frame_hdr     PROGBITS        0000000000007b94 007b94 0002ec 00   A  0   0  4
  [17] .eh_frame         PROGBITS        0000000000007e80 007e80 000e40 00   A  0   0  8
  [18] .init_array       INIT_ARRAY      0000000000009d30 008d30 000008 08  WA  0   0  8
  [19] .fini_array       FINI_ARRAY      0000000000009d38 008d38 000008 08  WA  0   0  8
  [20] .dynamic          DYNAMIC         0000000000009df8 008df8 0001e0 00   A  5   0  8
  [21] .got              PROGBITS        0000000000009fd8 008fd8 0000e8 08  WA  0   0  8
  [22] .got.plt          PROGBITS        000000000000a000 009000 000188 00  WA  0   0  8
  [23] .data             PROGBITS        000000000000a188 009188 000098 00  WA  0   0  8
  [24] .bss              NOBITS          000000000000a220 009220 0001c0 00  WA  0   0  4
  [25] .shstrtab         STRTAB          0000000000000000 009220 0000eb 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), l (large), p (processor specific)

```

## Current limitations
- Reading from a core file is not yet supported
- Statically linked binaries are not yet supported
- 32-bit binaries are not working correctly

