/*
 * This program will reconstruct a working executable ELF file from a process image
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <stdint.h>
#include <sys/wait.h>
#include <errno.h>
#include <ctype.h>
#include <elf.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "error.h"
#include "util.h"

#define DEFAULT_FILE "elf.bin"
#define NUM_SECTIONS 11

enum section_index {
    SH_NULL,
    SH_INTERP,
    SH_TEXT,
    SH_DYNSTR,
    SH_DYNAMIC,
    SH_RELA_PLT,
    SH_INIT,
    SH_GOT_PLT,
    SH_DATA,
    SH_DYNSYM,
    SH_SHSTRTAB,
};

struct string_table {
    enum section_index sidx;
    char *str;
    unsigned int len;
};

static struct string_table shstrtab[] = {
    { SH_NULL, "", 0 },
    { SH_INTERP, ".interp", 7 },
    { SH_TEXT, ".text", 5 },
    { SH_DYNSTR, ".dynstr", 7 },
    { SH_DYNAMIC, ".dynamic", 8 },
    { SH_RELA_PLT, ".rela.plt", 9 },
    { SH_INIT, ".init", 5 },
    { SH_GOT_PLT, ".got.plt", 8 },
    { SH_DATA, ".data", 5 },
    { SH_DYNSYM, ".dynsym", 7 },
    { SH_SHSTRTAB, ".shstrtab", 9 }
};

struct elf {
    elf_ehdr *ehdr;
    elf_phdr *phdr;
    elf_shdr *shdr;
    elf_dyn *dyn;
    elf_sym *sym;
    elf_rela *rela;
    unsigned char *dynstr;
    unsigned char *buf;
    unsigned int size;

    /* sections not associated with a segment, e.g. .symtab, .strtab etc. */
    struct section {
        unsigned char *buf;
        unsigned int size;
    } sections;
};


static bool verbose = false;
static char *output_file = NULL;

static elf_addr get_plt_addr(elf_addr init_addr);
static unsigned int get_strtbl_size(struct string_table *tbl, unsigned int len);
static int get_strtbl_idx(struct string_table *tbl, unsigned int len,
                          enum section_index section);

static int pid_read(pid_t pid, void *dst, const void *src, size_t len)
{
    long word;
    unsigned char *s = (unsigned char *) src;
    unsigned char *d = (unsigned char *) dst;
    size_t size = len / sizeof(long);

    while (size-- > 0) {
        errno = 0;
        word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);
        if (word == -1 && errno) {
            return -1;
        }
        *(long *) d = word;
        d += sizeof(long);
        s += sizeof(long);
    }
    return 0;
}

static void usage(char *prg)
{
    printf("Usage: %1$s [-hv] -p pid [output-file] or\n"
           "       %1$s [-hv] -r core [output-file]\n"
           "Options:\n"
           "  -p  Attach to process with process id pid\n"
           "  -r  Generate ELF executable from core file\n"
           "  -v  Print verbose output\n"
           "  -h  Print help message\n", prg);
}

static void write_file(struct elf *elf)

{
    int fd;

    if (!output_file)
        output_file = DEFAULT_FILE;
    printf("[+] Writing to file: %s\n", output_file);
    if ((fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755)) == -1)
        err_sys("open error");
    write(fd, elf->buf, elf->size);
    write(fd, elf->sections.buf, elf->sections.size);
    close(fd);
}

void generate_sht(struct elf *elf)
{
    size_t offset;
    unsigned int sh_strsize = 0;
    unsigned int shstrtab_elems = ARRAY_SIZE(shstrtab);

    offset = elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_DATA].sh_size;
    elf->sections.buf = xmalloc(get_strtbl_size(shstrtab, shstrtab_elems) +
                                elf->ehdr->e_shentsize * NUM_SECTIONS);

    /* section header string table .shstrtab */
    printf("[+] Generating .shstrtab\n");
    elf->sections.buf[sh_strsize++] = '\0';
    elf->shdr[SH_SHSTRTAB].sh_offset = offset++;
    for (int i = 1; i < ARRAY_SIZE(shstrtab); i++) {
        memcpy(elf->sections.buf + sh_strsize, shstrtab[i].str, shstrtab[i].len);
        offset += shstrtab[i].len + 1;
        sh_strsize += shstrtab[i].len;
        elf->sections.buf[sh_strsize++] = '\0';
    }
    elf->shdr[SH_SHSTRTAB].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                    SH_SHSTRTAB);
    elf->shdr[SH_SHSTRTAB].sh_type = SHT_STRTAB;
    elf->shdr[SH_SHSTRTAB].sh_flags = 0;
    elf->shdr[SH_SHSTRTAB].sh_addr = 0;
    elf->shdr[SH_SHSTRTAB].sh_size = sh_strsize;
    elf->shdr[SH_SHSTRTAB].sh_link = SHN_UNDEF;
    elf->shdr[SH_SHSTRTAB].sh_info = 0;
    elf->shdr[SH_SHSTRTAB].sh_addralign = 1;
    elf->shdr[SH_SHSTRTAB].sh_entsize = 0;

    /* update ELF header */
    elf->ehdr->e_shnum = NUM_SECTIONS;
    elf->ehdr->e_shstrndx = SH_SHSTRTAB;
    elf->ehdr->e_shoff = offset;
    memcpy(elf->buf, elf->ehdr, elf->ehdr->e_ehsize);

    /* section header table */
    printf("[+] Generating section header table\n");
    memcpy(elf->sections.buf + sh_strsize, elf->shdr, elf->ehdr->e_shentsize *
           NUM_SECTIONS);
    elf->sections.size = sh_strsize + elf->ehdr->e_shentsize * NUM_SECTIONS;
}

static void section_init(struct elf *elf)
{
    elf->shdr = xmalloc(elf->ehdr->e_shentsize * NUM_SECTIONS);

    /* index 0 marks undefined section references */
    elf->shdr[SH_NULL].sh_name = 0;
    elf->shdr[SH_NULL].sh_type = SHT_NULL;
    elf->shdr[SH_NULL].sh_flags = 0;
    elf->shdr[SH_NULL].sh_addr = 0;
    elf->shdr[SH_NULL].sh_offset = 0;
    elf->shdr[SH_NULL].sh_size = 0;
    elf->shdr[SH_NULL].sh_link = SHN_UNDEF;
    elf->shdr[SH_NULL].sh_info = 0;
    elf->shdr[SH_NULL].sh_addralign = 0;
    elf->shdr[SH_NULL].sh_entsize = 0;
}

static void read_dynamic_segment(struct elf *elf, elf_addr base)
{
    for (int i = 0; elf->dyn[i].d_tag != DT_NULL; i++) {
        switch (elf->dyn[i].d_tag) {
        case DT_PLTGOT: /* .got.plt section */
            elf->shdr[SH_GOT_PLT].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            if (elf->ehdr->e_type == ET_DYN)
                elf->dyn[i].d_un.d_ptr -= base;
            elf->shdr[SH_GOT_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                           SH_GOT_PLT);
            elf->shdr[SH_GOT_PLT].sh_type = SHT_PROGBITS;
            elf->shdr[SH_GOT_PLT].sh_flags = SHF_WRITE | SHF_ALLOC;
            elf->shdr[SH_GOT_PLT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_GOT_PLT].sh_size = 0; // ??
            elf->shdr[SH_GOT_PLT].sh_link = SHN_UNDEF;
            elf->shdr[SH_GOT_PLT].sh_info = 0;
            elf->shdr[SH_GOT_PLT].sh_addralign = 0; // ??
            elf->shdr[SH_GOT_PLT].sh_entsize = 0;
            break;
        case DT_STRTAB: /* .dynstr section */
            elf->shdr[SH_DYNSTR].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            elf->dynstr = elf->buf + elf->dyn[i].d_un.d_ptr - base;
            if (elf->ehdr->e_type == ET_DYN)
                elf->dyn[i].d_un.d_ptr -= base;
            elf->shdr[SH_DYNSTR].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                          SH_DYNSTR);
            elf->shdr[SH_DYNSTR].sh_type = SHT_STRTAB;
            elf->shdr[SH_DYNSTR].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNSTR].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_DYNSTR].sh_link = SHN_UNDEF;
            elf->shdr[SH_DYNSTR].sh_info = 0;
            elf->shdr[SH_DYNSTR].sh_addralign = 8;
            elf->shdr[SH_DYNSTR].sh_entsize = 0;
            break;
        case DT_STRSZ: /* size of the .dynstr section */
            elf->shdr[SH_DYNSTR].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_SYMTAB: /* .dynsym section */
            elf->shdr[SH_DYNSYM].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            elf->sym = (elf_sym *) (elf->buf + elf->dyn[i].d_un.d_ptr - base);
            if (elf->ehdr->e_type == ET_DYN)
                elf->dyn[i].d_un.d_ptr -= base;
            elf->shdr[SH_DYNSYM].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                          SH_DYNSYM);
            elf->shdr[SH_DYNSYM].sh_type = SHT_DYNSYM;
            elf->shdr[SH_DYNSYM].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNSYM].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_DYNSYM].sh_size = 0; // ??
            elf->shdr[SH_DYNSYM].sh_link = SH_DYNSTR;
            elf->shdr[SH_DYNSYM].sh_info = 0; // ??
            elf->shdr[SH_DYNSYM].sh_addralign = 8;
            break;
        case DT_SYMENT:
            elf->shdr[SH_DYNSYM].sh_entsize = elf->dyn[i].d_un.d_val;
            break;
        case DT_JMPREL: /* .rela.plt section */
            elf->shdr[SH_RELA_PLT].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            if (elf->ehdr->e_type == ET_DYN) {
                elf->dyn[i].d_un.d_ptr -= base;
                elf->rela = (elf_rela *) (elf->buf + elf->dyn[i].d_un.d_ptr);
            } else {
                elf->rela = (elf_rela *) (elf->buf + elf->dyn[i].d_un.d_ptr - base);
            }
            elf->shdr[SH_RELA_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                          SH_RELA_PLT);
            elf->shdr[SH_RELA_PLT].sh_type = SHT_RELA;
            elf->shdr[SH_RELA_PLT].sh_flags = SHF_ALLOC;
            elf->shdr[SH_RELA_PLT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_RELA_PLT].sh_link = SH_DYNSYM;
            elf->shdr[SH_RELA_PLT].sh_info = SH_GOT_PLT;
            elf->shdr[SH_RELA_PLT].sh_addralign = 8;
            elf->shdr[SH_RELA_PLT].sh_entsize = 0x18; // Same as .dynsym?
            break;
        case DT_PLTRELSZ: /* size of the .rela.plt section */
            elf->shdr[SH_RELA_PLT].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_INIT: /* .init section */
            elf->shdr[SH_INIT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                        SH_INIT);
            elf->shdr[SH_INIT].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INIT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
            elf->shdr[SH_INIT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_size = 0; // ??
            elf->shdr[SH_INIT].sh_link = SHN_UNDEF;
            elf->shdr[SH_INIT].sh_info = 0;
            elf->shdr[SH_INIT].sh_addralign = 4;
            elf->shdr[SH_INIT].sh_entsize = 0;
            break;
        case DT_RELA:
        case DT_REL:
        case DT_GNU_HASH:
        case DT_VERSYM:
            if (elf->ehdr->e_type == ET_DYN)
                elf->dyn[i].d_un.d_ptr -= base;
            break;
        default:
            break;
        }
    }
}

static bool read_segments(struct elf *elf, pid_t pid, elf_addr base)
{
    elf_xword offset = 0;

    printf("[+] Reading segments\n");

    /* get the size of the loadable segments */
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        if (elf->phdr[i].p_type == PT_LOAD) {
            if (elf->phdr[i].p_offset > elf->size)
                elf->size = elf->phdr[i].p_offset;
            elf->size += elf->phdr[i].p_filesz;
        }
    }
    elf->buf = xcalloc(1, elf->size);
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        if (elf->phdr[i].p_type == PT_LOAD) {
            if (elf->phdr[i].p_offset > offset)
                offset = elf->phdr[i].p_offset;
            if (pid_read(pid, elf->buf + offset, (void *) (base + elf->phdr[i].p_vaddr),
                          elf->phdr[i].p_filesz) == -1)
                return false;
        }
    }
    return true;
}

static void patch_got(struct elf *elf)
{
    elf_addr plt_addr;
    uint64_t plt_entry;
    uint64_t got_entry;

    plt_addr = get_plt_addr(elf->shdr[SH_INIT].sh_addr);

    /* clear GOT[1] and GOT[2] */
    memset(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           8 - elf->shdr[SH_DATA].sh_addr, 0, sizeof(uint64_t));
    memset(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           16 - elf->shdr[SH_DATA].sh_addr, 0, sizeof(uint64_t));

    /* r_offset contains the virtual address for the specific GOT entries */
    for (int i = 0; i < elf->shdr[SH_RELA_PLT].sh_size / sizeof(elf_rela); i++) {
        int sym_idx = ELF_R_SYM(elf->rela[i].r_info); /* symbol table index */

        /* 6 is the size of the first instruction in PLT[n] (jmp   [ebx + name1@GOT]) */
        /* 16 is the size of a PLT entry */
        plt_entry = plt_addr + (i + 1) * 16 + 6;
        got_entry = *((uint64_t *) (elf->buf + elf->shdr[SH_DATA].sh_offset +
                                    elf->rela[i].r_offset - elf->shdr[SH_DATA].sh_addr));
        if (plt_entry != got_entry) {
            memcpy(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->rela[i].r_offset -
                   elf->shdr[SH_DATA].sh_addr, &plt_entry, sizeof(uint64_t));
            printf("[+] Patching got[%d]:\n", i + 3);
            printf("    0x%lx\t0x%lx\t0x%lx\t%s\n",
                   elf->rela[i].r_offset, /* address of GOT entry */
                   elf->rela[i].r_info, /* symbol table index and type of relocation */
                   *((uint64_t *) (elf->buf + elf->shdr[SH_DATA].sh_offset +
                                   elf->rela[i].r_offset - elf->shdr[SH_DATA].sh_addr)),
                   elf->dynstr + elf->sym[sym_idx].st_name); /* name in the string table */
        }
    }
}

static void parse_elf(struct elf *elf, pid_t pid, unsigned char *buf,
                      uint64_t offset, size_t len)
{
    if (buf[EI_MAG0] != 0x7f || buf[EI_MAG1] != 'E' ||
        buf[EI_MAG2] != 'L' || buf[EI_MAG3] != 'F')
        err_quit("Not an ELF executable\n");
    elf->ehdr = (elf_ehdr *) buf;
    elf->phdr = (elf_phdr *) (buf + elf->ehdr->e_phoff);
    if (!read_segments(elf, pid, elf->ehdr->e_type == ET_EXEC ? 0 : offset)) {
        free(buf);
        free(elf->buf);
        err_quit("Error reading segments");
    }
    free(buf);
    elf->ehdr = (elf_ehdr *) elf->buf;
    elf->phdr = (elf_phdr *) (elf->buf + elf->ehdr->e_phoff);
    section_init(elf);
    if (elf->ehdr->e_type != ET_EXEC && elf->ehdr->e_type != ET_DYN)
        err_quit("ELF type not supported: %d", elf->ehdr->e_type);
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        switch (elf->phdr[i].p_type) {
        case PT_LOAD:
            if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_W)) {
                printf("    Data segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                elf->shdr[SH_DATA].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                            SH_DATA);
                elf->shdr[SH_DATA].sh_type = SHT_PROGBITS;
                elf->shdr[SH_DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
                elf->shdr[SH_DATA].sh_addr = elf->phdr[i].p_vaddr;
                elf->shdr[SH_DATA].sh_offset = elf->phdr[i].p_offset;
                elf->shdr[SH_DATA].sh_size = elf->phdr[i].p_filesz;
                elf->shdr[SH_DATA].sh_link = SHN_UNDEF;
                elf->shdr[SH_DATA].sh_info = 0;
                elf->shdr[SH_DATA].sh_addralign = elf->phdr[i].p_align;
                elf->shdr[SH_DATA].sh_entsize = 0;
            } else if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_X)) {
                printf("    Text segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                elf->shdr[SH_TEXT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                            SH_TEXT);
                elf->shdr[SH_TEXT].sh_type = SHT_PROGBITS;
                elf->shdr[SH_TEXT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
                elf->shdr[SH_TEXT].sh_addr = elf->phdr[i].p_vaddr;
                elf->shdr[SH_TEXT].sh_offset = elf->phdr[i].p_offset;
                elf->shdr[SH_TEXT].sh_size = elf->phdr[i].p_filesz;
                elf->shdr[SH_TEXT].sh_link = SHN_UNDEF;
                elf->shdr[SH_TEXT].sh_info = 0;
                elf->shdr[SH_TEXT].sh_addralign = elf->phdr[i].p_align;
                elf->shdr[SH_TEXT].sh_entsize = 0;
            }
            break;
        case PT_INTERP:
            elf->shdr[SH_INTERP].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                          SH_INTERP);
            elf->shdr[SH_INTERP].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INTERP].sh_flags = SHF_ALLOC;
            elf->shdr[SH_INTERP].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_INTERP].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_INTERP].sh_size = elf->phdr[i].p_memsz;
            elf->shdr[SH_INTERP].sh_link = SHN_UNDEF;
            elf->shdr[SH_INTERP].sh_info = 0;
            elf->shdr[SH_INTERP].sh_addralign = elf->phdr[i].p_align;
            elf->shdr[SH_INTERP].sh_entsize = 0;
            break;
        case PT_DYNAMIC:
            printf("    Dynamic segment: 0x%lx - 0x%lx (size: %lu bytes)\n",
                   elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_memsz,
                   elf->phdr[i].p_memsz);
            elf->dyn = (elf_dyn *) (elf->buf + elf->phdr[i].p_offset);
            elf->shdr[SH_DYNAMIC].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab),
                                                           SH_DYNAMIC);
            elf->shdr[SH_DYNAMIC].sh_type = SHT_DYNAMIC;
            /* whether the SHF_WRITE bit is set is processor-specific, check p_flags */
            elf->shdr[SH_DYNAMIC].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNAMIC].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_DYNAMIC].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_DYNAMIC].sh_size = elf->phdr[i].p_memsz;
            elf->shdr[SH_DYNAMIC].sh_link = SH_DYNSTR;
            elf->shdr[SH_DYNAMIC].sh_info = 0;
            elf->shdr[SH_DYNAMIC].sh_addralign = elf->phdr[i].p_align;
            elf->shdr[SH_DYNAMIC].sh_entsize = 0;
            read_dynamic_segment(elf, offset);
        default:
            break;
        }
    }
    if (!elf->dyn)
        err_quit("Cannot find dynamic segment");
    if (elf->rela)
        patch_got(elf);
}

int main(int argc, char **argv)
{
    char path[32];
    uint64_t mem_from;
    uint64_t mem_to;
    uint64_t size;
    pid_t pid = 0;;
    char *core = NULL;
    int opt;
    struct elf elf;
    unsigned char *buf;

    while ((opt = getopt(argc, argv, "p:r:hv")) != -1) {
        switch (opt) {
        case 'p':
            if (strlen(optarg) > 10) {
                err_quit("Invalid process id: %s", optarg);
            }
            pid = atoi(optarg);
            break;
        case 'r':
            // TODO: Need to support reading from a core file
            // core = optarg;
            break;
        case 'v':
            verbose = true;
            printf("verbose\n");
            break;
        case 'h':
        default:
            usage(argv[0]);
            exit(0);
        }
    }
    if (argc > optind) {
        output_file = argv[optind];
    }
    if (pid == 0 && !core) {
        usage(argv[0]);
        exit(0);
    }
    printf("[+] Reading headers\n");
    if (pid != 0) {
        FILE *fp;

        if (snprintf(path, 32, "/proc/%d/maps", pid) < 0)
            err_sys("snprintf error");

        /* open /proc/<pid>/maps */
        if (!(fp = fopen(path, "r")))
            err_sys("fopen error");

        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        waitpid(pid, NULL, 0); /* wait for tracee to stop */

        /* TODO: Need to check if ELF header is merged with text segment */
        if (fscanf(fp, "%lx-%lx", &mem_from, &mem_to) != 2)
            err_quit("Cannot read %s", path);
        size = mem_to - mem_from;
        buf = xmalloc(size);
        printf("    ELF header and .rodata: 0x%lx - 0x%lx (size: %lu bytes)\n",
                mem_from, mem_to, size);
        if (pid_read(pid, buf, (void * ) mem_from, size) == -1) {
            fclose(fp);
            free(buf);
            err_sys("Error reading ELF header");
        }
        fclose(fp);
    } else if (core) {
        int fd;
        unsigned char *buf;
        struct stat st;

        if ((fd = open(core, O_RDONLY)) == -1) {
            err_sys("open error");
        }
        if (fstat(fd, &st) == -1) {
            err_sys("fstat error");
        }
        if ((buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
            err_sys("mmap error");
    }
    memset(&elf, 0, sizeof(struct elf));
    parse_elf(&elf, pid, buf, mem_from, size);
    generate_sht(&elf);
    write_file(&elf);
    free(elf.buf);
    free(elf.sections.buf);
    free(elf.shdr);
}

unsigned int get_strtbl_size(struct string_table *tbl, unsigned int len)
{
    unsigned int size = 0;

    for (int i = 0; i < len; i++)
        size += tbl[i].len + 1;
    return size;
}

int get_strtbl_idx(struct string_table *tbl, unsigned int len,
                   enum section_index section)
{
    int idx = 0;

    for (int i = 0; i < len; i++) {
        if (i == section)
            return idx;
        idx += tbl[i].len + 1;
    }
    return -1;
}

elf_addr get_plt_addr(uint64_t init_addr)
{
    /*
     * TODO: search for the first entry
     *
     * .PLT0: push  DWORD PTR [ebx + 4]
     *        jmp   [ebx + 8]
     *        nop
     */
    elf_addr addr = init_addr + 0x1a; // 0x18

    return addr + (-addr & 0xf); /* align on a 16 byte boundary */
}
