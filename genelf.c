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
#include <limits.h>
#include "error.h"
#include "util.h"
#include "slist.h"

#define DEFAULT_FILE "elf.bin"
#define BUFSIZE 4096
#define UPDATE_ADDRESS(elf, addr, base)    \
    do {                                   \
        if ((elf)->ehdr->e_type == ET_DYN) \
            (addr) -= (base);              \
    } while (0)

#define ALIGN(a, b) (((a) + ((b) - 1)) & (-b))
#define IS_POWEROF2(x) ((x) > 0 && ((x) & (x - 1)) == 0)
#define GOTPLT_NELEMS(elf) \
    ((elf)->rel_type == DT_RELA ? \
     ((elf)->shdr[SH_RELA_PLT].sh_size / sizeof(elf_rela)) : \
     ((elf)->shdr[SH_REL_PLT].sh_size / sizeof(elf_rel)))
#define GOTPLT_NRESERVED_ELEMS 3
#define PLTENTSZ 16  /* PLT entry size */
#define GOT_NELEMS(elf) \
    ((elf)->rel_type == DT_RELA ? \
     ((elf)->shdr[SH_RELA_DYN].sh_size / (elf)->shdr[SH_RELA_DYN].sh_entsize) : \
     ((elf)->shdr[SH_REL_DYN].sh_size / (elf)->shdr[SH_REL_DYN].sh_entsize))
#define GOT_SIZE(elf) (GOT_NELEMS(elf) * 8)

/*
 * Use the correct relocation structure and return the value of the member at the given index.
 * t: type (plt or dyn)
 * m: struct member (without 'r_' prefix)
 * i: index
*/
#define get_rel(elf, t, m, i)                   \
    ((elf)->rel_type == DT_RELA ?               \
     CONCAT((elf)->rela_, t)[i].CONCAT(r_, m) : \
     CONCAT((elf)->rel_, t)[i].CONCAT(r_, m))

enum section_id {
    SH_NULL,
    SH_INTERP,
    SH_TEXT,
    SH_DYNSTR,
    SH_DYNAMIC,
    SH_RELA_DYN,
    SH_REL_DYN,
    SH_RELA_PLT,
    SH_REL_PLT,
    SH_INIT,
    SH_GOT_PLT,
    SH_DATA,
    SH_DYNSYM,
    SH_HASH,
    SH_GNU_HASH,
    SH_VERNEED,
    SH_VERSYM,
    SH_PLT,
    SH_PLT_GOT,
    SH_FINI,
    SH_SHSTRTAB,
    SH_NOTE,
    SH_EH_FRAME_HDR,
    SH_EH_FRAME,
    SH_RODATA,
    SH_INIT_ARRAY,
    SH_FINI_ARRAY,
    SH_GOT,
    SH_BSS,
    NUM_SECTIONS
};

struct string_table {
    enum section_id id;
    char *str;
    unsigned int len;
};

struct elf {
    elf_ehdr *ehdr;
    elf_phdr *phdr;
    elf_shdr *shdr;
    elf_dyn *dyn;
    elf_sym *sym;
    union {
        elf_rela *rela_plt;
        elf_rel *rel_plt;
    };
    union {
        elf_rela *rela_dyn;
        elf_rel *rel_dyn;
    };
    elf_sxword rel_type;
    unsigned char *dynstr;
    unsigned char *buf;
    unsigned int size;
    struct {
        elf_word nbucket;
        elf_word nchain;
        elf_word *bucket; /* hash table buckets array */
        elf_word *chain;  /* hash table chain array */
    } hash;
    struct {
        elf_word nbucket;
        elf_word symidx;    /* first accessible symbol in dynsym table */
        elf_word maskwords; /* bloom filter words */
        elf_word shift2;    /* bloom filter shift words */
        elf_addr *bloom;    /* bloom filter */
        elf_word *buckets;  /* hash table buckets array */
        elf_word *chain;    /* hash table value array */
    } gnu_hash;

    /* section headers sorted by offset */
    struct section_list {
        struct slist head;
        elf_shdr *shdr;
        int id;
    } *section_list;

    /*
     * Sections not associated with a segment, e.g. .symtab, .strtab etc., and
     * the section header table.
     */
    struct section {
        unsigned char *buf;
        unsigned int size;
    } sections;
};

static struct string_table shstrtab[] = {
    { SH_NULL, "", 0 },
    { SH_INTERP, ".interp", 7 },
    { SH_TEXT, ".text", 5 },
    { SH_DYNSTR, ".dynstr", 7 },
    { SH_DYNAMIC, ".dynamic", 8 },
    { SH_RELA_DYN, ".rela.dyn", 9 },
    { SH_REL_DYN, ".rel.dyn", 8 },
    { SH_RELA_PLT, ".rela.plt", 9 },
    { SH_RELA_PLT, ".rel.plt", 8 },
    { SH_INIT, ".init", 5 },
    { SH_GOT_PLT, ".got.plt", 8 },
    { SH_DATA, ".data", 5 },
    { SH_DYNSYM, ".dynsym", 7 },
    { SH_HASH, ".hash", 5 },
    { SH_GNU_HASH, ".gnu.hash", 9 },
    { SH_VERNEED, ".gnu.version_r", 14 },
    { SH_VERSYM, ".gnu.version", 12 },
    { SH_FINI, ".fini", 5 },
    { SH_SHSTRTAB, ".shstrtab", 9 },
    { SH_PLT_GOT, ".plt.got", 8 },
    { SH_NOTE, ".note", 5 },
    { SH_EH_FRAME_HDR, ".eh_frame_hdr", 13 },
    { SH_EH_FRAME, ".eh_frame", 9 },
    { SH_RODATA, ".rodata", 7 },
    { SH_INIT_ARRAY, ".init_array", 11 },
    { SH_FINI_ARRAY, ".fini_array", 11 },
    { SH_BSS, ".bss", 4 },

};

/*
 * Push and jmp use 1 byte opcodes and modR/M byte, nop uses two bytes opcode
 * and modR/M byte
*/
static const uint8_t plt_pattern[] = {
    0xff, 0x35, 0x00, 0x00, 0x00, 0x00, /* push <indirect address> */
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00, /* jmp <indirect address> */
    0x0f, 0x1f, 0x40, 0x00              /* nop */
};

static bool valid_hash = false;
static bool valid_gnu_hash = false;
static bool verbose = false;
static char *output_file = NULL;
static int ph_data, ph_text, ph_rodata;

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

static int cmp_offset(const struct slist *p1, const struct slist *p2)
{
    return ((struct section_list *) p1)->shdr->sh_offset - ((struct section_list *) p2)->shdr->sh_offset;
}

static void section_list_add(struct elf *elf, int sid)
{
    struct section_list *n;

    n = xcalloc(1, sizeof(*n));
    n->shdr = &elf->shdr[sid];
    n->id = sid;
    slist_add(&elf->section_list->head, (struct slist *) n, cmp_offset);
}

void section_list_free(struct elf *elf)
{
    if (!elf->section_list)
        return;

    struct slist *head = &elf->section_list->head;

    while (head) {
        struct section_list *t;

        t = (struct section_list *) head;
        head = head->next;
        free(t);
    }
}

static int get_section_idx(struct elf *elf, int section_id)
{
    struct slist *n;
    int c = 0;

    n = &elf->section_list->head;
    SLIST_FOREACH(n) {
        if (((struct section_list *) n)->id == section_id)
            return c;
        c++;
    }
    return -1;
}

static unsigned int get_strtbl_size(struct string_table *tbl, unsigned int len)
{
    unsigned int size = 0;

    for (int i = 0; i < len; i++)
        size += tbl[i].len + 1;
    return size;
}

static int get_strtbl_idx(struct string_table *tbl, unsigned int len, int sid)
{
    int idx = 0;

    for (int i = 0; i < len; i++) {
        if (tbl[i].id == sid)
            return idx;
        idx += tbl[i].len + 1;
    }
    return -1;
}

static elf_addr get_plt_addr(struct elf *elf)
{
    for (elf_addr i = elf->shdr[SH_INIT].sh_addr; i < elf->shdr[SH_TEXT].sh_addr
             + elf->shdr[SH_TEXT].sh_size - 16; i++) {
        if (memcmp(&elf->buf[i], &plt_pattern[0], 2) == 0 &&
            memcmp(&elf->buf[i + 6], &plt_pattern[6], 2) == 0 &&
            memcmp(&elf->buf[i + 12], &plt_pattern[12], 3) == 0) {
            return i;
        }
    }
    return -1;
}

/* get the address of the .got section */
static elf_addr get_got_addr(struct elf *elf)
{
    for (int i = 0; i < GOT_NELEMS(elf); i++) {
        if (ELF_ST_TYPE(get_rel(elf, dyn, info, i)) == R_GLOB_DAT)
            return get_rel(elf, dyn, offset, i);
    }
    return 0;
}

static int get_nsymbols(struct elf *elf)
{
    if (valid_hash)
        return elf->hash.nchain;
    if (valid_gnu_hash) {
        elf_word max;
        elf_word *hashval;

        max = 0;
        for (unsigned int i = 0; i < elf->gnu_hash.nbucket; i++) {
            if (elf->gnu_hash.buckets[i] > max)
                max = elf->gnu_hash.buckets[i];
        }
        hashval = elf->gnu_hash.chain + max;
        do {
            max++;
        } while ((*hashval++ & 1) == 0);
        return max;
    }
    return 0;
}

static inline int get_hashtab_size(struct elf *elf)
{
    return 2 * sizeof(elf_word) + elf->hash.nbucket * sizeof(elf_word) +
        elf->hash.nchain * sizeof(elf_word);
}

static inline int get_gnuhashtab_size(struct elf *elf)
{
    elf_word bloom_size;

    bloom_size = (ELF_WORD_SIZE / 32) * elf->gnu_hash.maskwords;
    return 4 * sizeof(elf_word) + bloom_size * sizeof(elf_addr) +
        elf->gnu_hash.nbucket * sizeof(elf_word);
}

static int get_idx_last_local_sym(struct elf *elf)
{
    for (int i = 0; i < get_nsymbols(elf); i++) {
        if (ELF_ST_BIND(elf->sym[i].st_info) != STB_LOCAL)
            return i;
    }
    return 0;
}

static int mem_read(pid_t pid, void *dst, const void *src, size_t len)
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

static void write_file(struct elf *elf)
{
    int fd;

    printf("[+] Writing to file: %s\n", output_file);
    if ((fd = open(output_file, O_WRONLY | O_CREAT | O_TRUNC, 0755)) == -1)
        err_sys("open error");
    write(fd, elf->buf, elf->size);
    write(fd, elf->sections.buf, elf->sections.size);
    close(fd);
}

static void generate_sht(struct elf *elf)
{
    size_t offset;
    unsigned int sh_strsize = 0;
    unsigned int shstrtab_elems = ARRAY_SIZE(shstrtab);
    struct slist *n;
    int c = 0;

    elf->size = offset = elf->phdr[ph_data].p_offset + elf->phdr[ph_data].p_filesz;
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
    elf->shdr[SH_SHSTRTAB].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_SHSTRTAB);
    elf->shdr[SH_SHSTRTAB].sh_type = SHT_STRTAB;
    elf->shdr[SH_SHSTRTAB].sh_flags = 0;
    elf->shdr[SH_SHSTRTAB].sh_addr = 0;
    elf->shdr[SH_SHSTRTAB].sh_offset = elf->phdr[ph_data].p_offset + elf->phdr[ph_data].p_filesz;
    elf->shdr[SH_SHSTRTAB].sh_size = sh_strsize;
    elf->shdr[SH_SHSTRTAB].sh_link = SHN_UNDEF;
    elf->shdr[SH_SHSTRTAB].sh_info = 0;
    elf->shdr[SH_SHSTRTAB].sh_addralign = 1;
    elf->shdr[SH_SHSTRTAB].sh_entsize = 0;
    section_list_add(elf, SH_SHSTRTAB);

    /* section header table */
    printf("[+] Generating section header table\n");
    elf->sections.size = sh_strsize + elf->ehdr->e_shentsize * slist_size(&elf->section_list->head);

    /* write section header table to buf */
    n = &elf->section_list->head;
    SLIST_FOREACH(n) {
        memcpy(elf->sections.buf + sh_strsize + c * elf->ehdr->e_shentsize,
               ((struct section_list *) n)->shdr, elf->ehdr->e_shentsize);
        c++;
    }

    /* update ELF header */
    elf->ehdr->e_shnum = slist_size(&elf->section_list->head);
    elf->ehdr->e_shstrndx = slist_size(&elf->section_list->head) - 1;
    elf->ehdr->e_shoff = offset;
    memcpy(elf->buf, elf->ehdr, elf->ehdr->e_ehsize);
}

static elf_addr read_process(struct elf *elf, FILE *fp, char *name, pid_t pid)
{
    char line[BUFSIZE];
    char path[PATH_MAX];
    elf_addr from, to;
    elf_off offset;
    elf_addr base;

    offset = 0;
    while (fgets(line, BUFSIZE, fp)) {
        if (sscanf(line, "%lx-%lx %*s %*x %*s %*d %s", &from, &to, path) < 3)
            continue;
        if (strstr(path, name) != NULL)
            break;
    }
    elf->buf = xmalloc(to - from);
    elf->size = to - from;
    if (mem_read(pid, elf->buf, (void *) from, to - from) == -1) {
        free(elf->buf);
        return 0;
    }
    if (elf->buf[EI_MAG0] != 0x7f || elf->buf[EI_MAG1] != 'E' ||
        elf->buf[EI_MAG2] != 'L' || elf->buf[EI_MAG3] != 'F') {
        err_msg("Not an ELF executable\n");
        free(elf->buf);
        return 0;
    }
    base = from;
    while (fgets(line, BUFSIZE, fp)) {
        if (sscanf(line, "%lx-%lx %*s %lx %*s %*d %s", &from, &to, &offset, path) == 4) {
            if (strstr(path, name) == NULL)
                break;
            elf->size += to - from;
            elf->buf = xrealloc(elf->buf, elf->size);
            if (mem_read(pid, elf->buf + offset, (void *) from, to - from) == -1) {
                free(elf->buf);
                return 0;
            };
        }
    }
    return base;
}

char *get_procname(pid_t pid)
{
    char cmdline[PATH_MAX];
    char buf[BUFSIZE];
    FILE *fp;
    char *p;

    snprintf(cmdline, PATH_MAX, "/proc/%d/cmdline", pid);
    if ((fp = fopen(cmdline, "r")) == NULL)
        return NULL;
    if (fgets(buf, BUFSIZE, fp) == NULL) {
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    if ((p = strrchr(buf, '/')) != NULL)
        p++;
    else
        p = buf;
    return strdup(p);
}

static void update_plt_section(struct elf *elf, elf_addr addr)
{
    elf->shdr[SH_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_RELA_PLT) + 5;
    elf->shdr[SH_PLT].sh_type = SHT_PROGBITS;
    elf->shdr[SH_PLT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
    elf->shdr[SH_PLT].sh_addr = addr;
    elf->shdr[SH_PLT].sh_offset = addr;
    elf->shdr[SH_PLT].sh_link = SHN_UNDEF;
    elf->shdr[SH_PLT].sh_info = 0;
    elf->shdr[SH_PLT].sh_addralign = 16;
    elf->shdr[SH_PLT].sh_entsize = PLTENTSZ;
    elf->shdr[SH_PLT].sh_size = PLTENTSZ * GOTPLT_NELEMS(elf) + sizeof(plt_pattern);
    section_list_add(elf, SH_PLT);
    elf->shdr[SH_PLT_GOT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_PLT_GOT);
    elf->shdr[SH_PLT_GOT].sh_type = SHT_PROGBITS;
    elf->shdr[SH_PLT_GOT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
    elf->shdr[SH_PLT_GOT].sh_addr = addr + elf->shdr[SH_PLT].sh_size;
    elf->shdr[SH_PLT_GOT].sh_offset = addr + elf->shdr[SH_PLT].sh_size;
    elf->shdr[SH_PLT_GOT].sh_link = SHN_UNDEF;
    elf->shdr[SH_PLT_GOT].sh_info = 0;
    elf->shdr[SH_PLT_GOT].sh_addralign = 8;
    elf->shdr[SH_PLT_GOT].sh_entsize = 8;
    elf->shdr[SH_PLT_GOT].sh_size = 8; /* FIXME: Find correct size */
    section_list_add(elf, SH_PLT_GOT);
}

static bool patch_got(struct elf *elf, elf_addr base)
{
    elf_addr plt_addr;
    elf_addr plt_entry;
    elf_addr got_entry;

    /*
     * Set the size of .got.plt based on the size of the .rela.plt relocation table,
     * which holds information to relocate entries in the .got.plt section.
     */
    elf->shdr[SH_GOT_PLT].sh_size = (GOTPLT_NELEMS(elf) + GOTPLT_NRESERVED_ELEMS) * sizeof(elf_addr);

    /* set the offset based on the data offset and the address of the GOT entry */
    elf->shdr[SH_GOT_PLT].sh_offset = elf->phdr[ph_data].p_offset + get_rel(elf, plt, offset, 0) -
        elf->phdr[ph_data].p_vaddr - GOTPLT_NRESERVED_ELEMS * sizeof(elf_addr);

    if ((plt_addr = get_plt_addr(elf)) == -1)
        return false;
    update_plt_section(elf, plt_addr);
    elf->shdr[SH_INIT].sh_size = plt_addr - elf->shdr[SH_INIT].sh_addr;

    /* clear GOT[1] and GOT[2] */
    memset(elf->buf + elf->phdr[ph_data].p_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           8 - elf->phdr[ph_data].p_vaddr, 0, sizeof(elf_addr));
    memset(elf->buf + elf->phdr[ph_data].p_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           16 - elf->phdr[ph_data].p_vaddr, 0, sizeof(elf_addr));

    /* r_offset contains the virtual address for the specific GOT entries */
    for (int i = 0; i < GOTPLT_NELEMS(elf); i++) {
        int sym_idx = ELF_R_SYM(get_rel(elf, plt, info, i)); /* symbol table index */

        /* 6 is the size of the first instruction in PLT[n] (jmp [ebx + name1@GOT]) */
        plt_entry = plt_addr + (i + 1) * PLTENTSZ + 6;
        got_entry = *((elf_addr *) (elf->buf + elf->phdr[ph_data].p_offset +
                                    get_rel(elf, plt, offset, i) - elf->phdr[ph_data].p_vaddr));
        UPDATE_ADDRESS(elf, got_entry, base);
        if (plt_entry != got_entry) {
            memcpy(elf->buf + elf->phdr[ph_data].p_offset + get_rel(elf, plt, offset, i) -
                   elf->phdr[ph_data].p_vaddr, &plt_entry, sizeof(elf_addr));
            printf("[+] Patching got[%d]:\n", i + 3);
            printf("    0x%lx\t0x%lx\t0x%lx\t%s\n",
                   get_rel(elf, plt, offset, i), /* address of GOT entry */
                   get_rel(elf, plt, info, i),   /* symbol table index and type of relocation */
                   *((elf_addr *) (elf->buf + elf->phdr[ph_data].p_offset +
                                   get_rel(elf, plt, offset, i) - elf->phdr[ph_data].p_vaddr)),
                   elf->dynstr + elf->sym[sym_idx].st_name); /* name in the string table */
        } else if (elf->ehdr->e_type == ET_DYN) {
            /* update got to the relative address for pies */
            memcpy(elf->buf + elf->phdr[ph_data].p_offset + get_rel(elf, plt, offset, i) -
                   elf->phdr[ph_data].p_vaddr, &got_entry, sizeof(elf_addr));
        }
    }
    return true;
}

static void read_dynamic_segment(struct elf *elf, elf_addr base)
{
    elf_word *hashtab;
    elf_addr jmprel;

    for (int i = 0; elf->dyn[i].d_tag != DT_NULL; i++) {
        switch (elf->dyn[i].d_tag) {
        case DT_PLTGOT: /* .got.plt section */
            elf->shdr[SH_GOT_PLT].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->shdr[SH_GOT_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_GOT_PLT);
            elf->shdr[SH_GOT_PLT].sh_type = SHT_PROGBITS;
            elf->shdr[SH_GOT_PLT].sh_flags = SHF_WRITE | SHF_ALLOC;
            elf->shdr[SH_GOT_PLT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_GOT_PLT].sh_link = SHN_UNDEF;
            elf->shdr[SH_GOT_PLT].sh_info = 0;
            elf->shdr[SH_GOT_PLT].sh_addralign = sizeof(elf_addr);
            elf->shdr[SH_GOT_PLT].sh_entsize = 0;
            section_list_add(elf, SH_GOT_PLT);
            break;
        case DT_STRTAB: /* .dynstr section */
            elf->shdr[SH_DYNSTR].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            elf->dynstr = elf->buf + elf->dyn[i].d_un.d_ptr - base;
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->shdr[SH_DYNSTR].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_DYNSTR);
            elf->shdr[SH_DYNSTR].sh_type = SHT_STRTAB;
            elf->shdr[SH_DYNSTR].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNSTR].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_DYNSTR].sh_link = SHN_UNDEF;
            elf->shdr[SH_DYNSTR].sh_info = 0;
            elf->shdr[SH_DYNSTR].sh_addralign = 8;
            elf->shdr[SH_DYNSTR].sh_entsize = 0;
            section_list_add(elf, SH_DYNSTR);
            break;
        case DT_STRSZ: /* size of the .dynstr section */
            elf->shdr[SH_DYNSTR].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_SYMTAB: /* .dynsym section */
            elf->shdr[SH_DYNSYM].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            elf->sym = (elf_sym *) (elf->buf + elf->dyn[i].d_un.d_ptr - base);
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->shdr[SH_DYNSYM].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_DYNSYM);
            elf->shdr[SH_DYNSYM].sh_type = SHT_DYNSYM;
            elf->shdr[SH_DYNSYM].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNSYM].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_DYNSYM].sh_addralign = 8;
            section_list_add(elf, SH_DYNSYM);
            break;
        case DT_SYMENT:
            elf->shdr[SH_DYNSYM].sh_entsize = elf->dyn[i].d_un.d_val;
            break;
        case DT_RELA: /* .rela.dyn section */
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->rela_dyn = (elf_rela *) (elf->buf + elf->dyn[i].d_un.d_ptr);
            elf->shdr[SH_RELA_DYN].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_RELA_DYN].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_RELA_DYN);
            elf->shdr[SH_RELA_DYN].sh_type = SHT_RELA;
            elf->shdr[SH_RELA_DYN].sh_flags = SHF_ALLOC;
            elf->shdr[SH_RELA_DYN].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_RELA_DYN].sh_info = 0;
            elf->shdr[SH_RELA_DYN].sh_addralign = 8;
            section_list_add(elf, SH_RELA_DYN);
            break;
        case DT_RELASZ:
            elf->shdr[SH_RELA_DYN].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_RELAENT:
            elf->shdr[SH_RELA_DYN].sh_entsize = elf->dyn[i].d_un.d_val;
            break;
        case DT_REL:
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->rel_dyn = (elf_rel *) (elf->buf + elf->dyn[i].d_un.d_ptr);
            elf->shdr[SH_REL_DYN].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_REL_DYN].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_REL_DYN);
            elf->shdr[SH_REL_DYN].sh_type = SHT_REL;
            elf->shdr[SH_REL_DYN].sh_flags = SHF_ALLOC;
            elf->shdr[SH_REL_DYN].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_REL_DYN].sh_info = 0;
            elf->shdr[SH_REL_DYN].sh_addralign = 8;
            section_list_add(elf, SH_REL_DYN);
            break;
        case DT_RELSZ:
            elf->shdr[SH_REL_DYN].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_RELENT:
            elf->shdr[SH_REL_DYN].sh_entsize = elf->dyn[i].d_un.d_val;
            break;
        case DT_JMPREL: /* .rela.plt section */
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            jmprel = elf->dyn[i].d_un.d_ptr;
            break;
        case DT_PLTRELSZ: /* size of the .rela.plt section */
            elf->shdr[SH_RELA_PLT].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_PLTREL:
            elf->rel_type = elf->dyn[i].d_un.d_val;
            break;
        case DT_INIT: /* .init section */
            elf->shdr[SH_INIT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_INIT);
            elf->shdr[SH_INIT].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INIT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
            elf->shdr[SH_INIT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_link = SHN_UNDEF;
            elf->shdr[SH_INIT].sh_info = 0;
            elf->shdr[SH_INIT].sh_addralign = 4;
            elf->shdr[SH_INIT].sh_entsize = 0;
            section_list_add(elf, SH_INIT);
            break;
        case DT_HASH:
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            hashtab = (elf_word *) (elf->buf + elf->dyn[i].d_un.d_ptr);
            elf->hash.nbucket = hashtab[0];
            elf->hash.nchain = hashtab[1];
            elf->hash.bucket = hashtab + 2;
            elf->hash.chain = elf->hash.bucket + elf->hash.nbucket;
            valid_hash = elf->hash.nbucket > 0 && elf->hash.nchain > 0 && elf->hash.bucket != NULL;
            elf->shdr[SH_HASH].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_HASH);
            elf->shdr[SH_HASH].sh_type = SHT_HASH;
            elf->shdr[SH_HASH].sh_flags = SHF_ALLOC;
            elf->shdr[SH_HASH].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_HASH].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_HASH].sh_size = get_hashtab_size(elf);
            elf->shdr[SH_HASH].sh_info = 0;
            elf->shdr[SH_HASH].sh_addralign = 8;
            elf->shdr[SH_HASH].sh_entsize = 0;
            section_list_add(elf, SH_HASH);
            break;
        case DT_INIT_ARRAY:
            elf->shdr[SH_INIT_ARRAY].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_INIT_ARRAY);
            elf->shdr[SH_INIT_ARRAY].sh_type = SHT_INIT_ARRAY;
            elf->shdr[SH_INIT_ARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
            elf->shdr[SH_INIT_ARRAY].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT_ARRAY].sh_offset = elf->dyn[i].d_un.d_ptr - 0x1000; /* FIXME: Find correct offset */
            elf->shdr[SH_INIT_ARRAY].sh_link = SHN_UNDEF;
            elf->shdr[SH_INIT_ARRAY].sh_info = 0;
            elf->shdr[SH_INIT_ARRAY].sh_addralign = 8;
            elf->shdr[SH_INIT_ARRAY].sh_entsize = sizeof(elf_addr);
            section_list_add(elf, SH_INIT_ARRAY);
            break;
        case DT_FINI_ARRAY:
            elf->shdr[SH_FINI_ARRAY].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_FINI_ARRAY);
            elf->shdr[SH_FINI_ARRAY].sh_type = SHT_FINI_ARRAY;
            elf->shdr[SH_FINI_ARRAY].sh_flags = SHF_WRITE | SHF_ALLOC;
            elf->shdr[SH_FINI_ARRAY].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_FINI_ARRAY].sh_offset = elf->dyn[i].d_un.d_ptr - 0x1000; /* FIXME: Find correct offset */
            elf->shdr[SH_FINI_ARRAY].sh_link = SHN_UNDEF;
            elf->shdr[SH_FINI_ARRAY].sh_info = 0;
            elf->shdr[SH_FINI_ARRAY].sh_addralign = 8;
            elf->shdr[SH_FINI_ARRAY].sh_entsize = sizeof(elf_addr);
            section_list_add(elf, SH_FINI_ARRAY);
            break;
        case DT_INIT_ARRAYSZ:
            elf->shdr[SH_INIT_ARRAY].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_FINI_ARRAYSZ:
            elf->shdr[SH_FINI_ARRAY].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_GNU_HASH:
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            hashtab = (elf_word *) (elf->buf + elf->dyn[i].d_un.d_ptr);
            elf->gnu_hash.nbucket = hashtab[0];
            elf->gnu_hash.symidx = hashtab[1];
            elf->gnu_hash.maskwords = hashtab[2];
            elf->gnu_hash.shift2 = hashtab[3];
            elf->gnu_hash.bloom = (elf_addr *) hashtab + 4;
            elf->gnu_hash.buckets = hashtab + 4 + (ELF_WORD_SIZE / 32) * elf->gnu_hash.maskwords;;
            elf->gnu_hash.chain = elf->gnu_hash.buckets + elf->gnu_hash.nbucket -
                elf->gnu_hash.symidx;
            valid_gnu_hash = IS_POWEROF2(elf->gnu_hash.maskwords) && elf->gnu_hash.nbucket > 0 &&
                elf->gnu_hash.buckets != 0;
            elf->shdr[SH_GNU_HASH].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_GNU_HASH);
            elf->shdr[SH_GNU_HASH].sh_type = SHT_GNU_HASH;
            elf->shdr[SH_GNU_HASH].sh_flags = SHF_ALLOC;
            elf->shdr[SH_GNU_HASH].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_GNU_HASH].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_GNU_HASH].sh_size = get_gnuhashtab_size(elf);
            elf->shdr[SH_GNU_HASH].sh_info = 0;
            elf->shdr[SH_GNU_HASH].sh_addralign = 8;
            elf->shdr[SH_GNU_HASH].sh_entsize = 0;
            section_list_add(elf, SH_GNU_HASH);
            break;
        case DT_FINI: /* .fini section */
            elf->shdr[SH_FINI].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_FINI);
            elf->shdr[SH_FINI].sh_type = SHT_PROGBITS;
            elf->shdr[SH_FINI].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
            elf->shdr[SH_FINI].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_FINI].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_FINI].sh_link = SHN_UNDEF;
            elf->shdr[SH_FINI].sh_info = 0;
            elf->shdr[SH_FINI].sh_addralign = 4;
            elf->shdr[SH_FINI].sh_entsize = 0;
            section_list_add(elf, SH_FINI);
            break;
        case DT_VERNEED: /* .gnu_version_r section */
            elf->shdr[SH_VERNEED].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_VERNEED);
            elf->shdr[SH_VERNEED].sh_type = SHT_GNU_verneed;
            elf->shdr[SH_VERNEED].sh_flags = SHF_ALLOC;
            elf->shdr[SH_VERNEED].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_VERNEED].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_VERNEED].sh_link = SHN_UNDEF;
            elf->shdr[SH_VERNEED].sh_info = 0;
            elf->shdr[SH_VERNEED].sh_addralign = 8;
            elf->shdr[SH_VERNEED].sh_entsize = 0;
            section_list_add(elf, SH_VERNEED);
            break;
        case DT_VERNEEDNUM: /* number of needed versions */
            elf->shdr[SH_VERNEED].sh_info = elf->dyn[i].d_un.d_val;
            break;
        case DT_VERSYM: /* .gnu_version section */
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->shdr[SH_VERSYM].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_VERSYM);
            elf->shdr[SH_VERSYM].sh_type = SHT_GNU_versym;
            elf->shdr[SH_VERSYM].sh_flags = SHF_ALLOC;
            elf->shdr[SH_VERSYM].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_VERSYM].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_VERSYM].sh_link = SHN_UNDEF;
            elf->shdr[SH_VERSYM].sh_info = 0;
            elf->shdr[SH_VERSYM].sh_addralign = 2;
            elf->shdr[SH_VERSYM].sh_entsize = sizeof(elf_half);
            section_list_add(elf, SH_VERSYM);
            break;
        default:
            break;
        }
    }
    if (elf->rel_type == DT_REL) {
        elf->rel_plt = (elf_rel *) (elf->buf + jmprel);
        elf->shdr[SH_REL_PLT].sh_offset = jmprel;
        elf->shdr[SH_REL_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_REL_PLT);
        elf->shdr[SH_REL_PLT].sh_type = SHT_REL;
        elf->shdr[SH_REL_PLT].sh_flags = SHF_ALLOC | SHF_INFO_LINK;
        elf->shdr[SH_REL_PLT].sh_addr = jmprel;
        elf->shdr[SH_REL_PLT].sh_addralign = 8;
        elf->shdr[SH_REL_PLT].sh_entsize = sizeof(elf_rel);
        section_list_add(elf, SH_REL_PLT);
    } else {
        elf->rela_plt = (elf_rela *) (elf->buf + jmprel);
        elf->shdr[SH_RELA_PLT].sh_offset = jmprel;
        elf->shdr[SH_RELA_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_RELA_PLT);
        elf->shdr[SH_RELA_PLT].sh_type = SHT_RELA;
        elf->shdr[SH_RELA_PLT].sh_flags = SHF_ALLOC | SHF_INFO_LINK;
        elf->shdr[SH_RELA_PLT].sh_addr = jmprel;
        elf->shdr[SH_RELA_PLT].sh_addralign = 8;
        elf->shdr[SH_RELA_PLT].sh_entsize = sizeof(elf_rela);
        section_list_add(elf, SH_RELA_PLT);
    }
}

static bool parse_elf(struct elf *elf, pid_t pid, elf_addr base)
{
    int nsym;
    bool ret = false;

    elf->ehdr = (elf_ehdr *) elf->buf;
    elf->phdr = (elf_phdr *) (elf->buf + elf->ehdr->e_phoff);
    elf->shdr = xcalloc(NUM_SECTIONS, sizeof(*elf->shdr));
    elf->section_list = calloc(1, sizeof(*elf->section_list));
    elf->section_list->shdr = &elf->shdr[SH_NULL];
    elf->section_list->id = SH_NULL;
    if (elf->ehdr->e_type != ET_EXEC && elf->ehdr->e_type != ET_DYN) {
        fprintf(stderr, "ELF type not supported: %d\n", elf->ehdr->e_type);
        return false;
    }
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        switch (elf->phdr[i].p_type) {
        case PT_LOAD:
            if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_W)) {
                printf("    Data segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                ph_data = i;
                elf->shdr[SH_DATA].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_DATA);
                elf->shdr[SH_DATA].sh_type = SHT_PROGBITS;
                elf->shdr[SH_DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
                elf->shdr[SH_DATA].sh_link = SHN_UNDEF;
                elf->shdr[SH_DATA].sh_info = 0;
                elf->shdr[SH_DATA].sh_addralign = 8;
                elf->shdr[SH_DATA].sh_entsize = 0;
            } else if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_X)) {
                printf("    Text segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                ph_text = i;
                elf->shdr[SH_TEXT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_TEXT);
                elf->shdr[SH_TEXT].sh_type = SHT_PROGBITS;
                elf->shdr[SH_TEXT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
                elf->shdr[SH_TEXT].sh_link = SHN_UNDEF;
                elf->shdr[SH_TEXT].sh_info = 0;
                elf->shdr[SH_TEXT].sh_addralign = 16;
                elf->shdr[SH_TEXT].sh_entsize = 0;
            } else if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == PF_R) {
                ph_rodata = i;
                elf->shdr[SH_RODATA].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_RODATA);
                elf->shdr[SH_RODATA].sh_type = SHT_PROGBITS;
                elf->shdr[SH_RODATA].sh_flags = SHF_ALLOC;
                elf->shdr[SH_RODATA].sh_addr = elf->phdr[i].p_vaddr;
                elf->shdr[SH_RODATA].sh_offset = elf->phdr[i].p_offset;
                elf->shdr[SH_RODATA].sh_link = SHN_UNDEF;
                elf->shdr[SH_RODATA].sh_info = 0;
                elf->shdr[SH_RODATA].sh_addralign = 8;
                elf->shdr[SH_RODATA].sh_entsize = 0;
                section_list_add(elf, SH_RODATA);
            }
            break;
        case PT_INTERP:
            elf->shdr[SH_INTERP].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_INTERP);
            elf->shdr[SH_INTERP].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INTERP].sh_flags = SHF_ALLOC;
            elf->shdr[SH_INTERP].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_INTERP].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_INTERP].sh_size = elf->phdr[i].p_filesz;
            elf->shdr[SH_INTERP].sh_link = SHN_UNDEF;
            elf->shdr[SH_INTERP].sh_info = 0;
            elf->shdr[SH_INTERP].sh_addralign = elf->phdr[i].p_align;
            elf->shdr[SH_INTERP].sh_entsize = 0;
            section_list_add(elf, SH_INTERP);
            break;
        case PT_DYNAMIC:
            printf("    Dynamic segment: 0x%lx - 0x%lx (size: %lu bytes)\n",
                   elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_memsz,
                   elf->phdr[i].p_memsz);
            elf->dyn = (elf_dyn *) (elf->buf + elf->phdr[i].p_offset);
            elf->shdr[SH_DYNAMIC].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_DYNAMIC);
            elf->shdr[SH_DYNAMIC].sh_type = SHT_DYNAMIC;
            /* whether the SHF_WRITE bit is set is processor-specific, check p_flags */
            elf->shdr[SH_DYNAMIC].sh_flags = SHF_ALLOC;
            elf->shdr[SH_DYNAMIC].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_DYNAMIC].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_DYNAMIC].sh_size = elf->phdr[i].p_filesz;
            elf->shdr[SH_DYNAMIC].sh_info = 0;
            elf->shdr[SH_DYNAMIC].sh_addralign = elf->phdr[i].p_align;
            elf->shdr[SH_DYNAMIC].sh_entsize = 0;
            section_list_add(elf, SH_DYNAMIC);
            read_dynamic_segment(elf, base);
            nsym = get_nsymbols(elf);
            elf->shdr[SH_DYNSYM].sh_size = nsym * elf->shdr[SH_DYNSYM].sh_entsize;
            elf->shdr[SH_VERSYM].sh_size = nsym * sizeof(elf_half);
            elf->shdr[SH_VERNEED].sh_size = elf->shdr[SH_RELA_DYN].sh_addr - elf->shdr[SH_VERNEED].sh_addr;
            break;
        case PT_NOTE:
            elf->shdr[SH_NOTE].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_NOTE);
            elf->shdr[SH_NOTE].sh_type = SHT_NOTE;
            elf->shdr[SH_NOTE].sh_flags = SHF_ALLOC;
            elf->shdr[SH_NOTE].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_NOTE].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_NOTE].sh_size = elf->phdr[i].p_filesz;
            elf->shdr[SH_NOTE].sh_link = SHN_UNDEF;
            elf->shdr[SH_NOTE].sh_info = 0;
            elf->shdr[SH_NOTE].sh_addralign = 4;
            elf->shdr[SH_NOTE].sh_entsize = 0;
            section_list_add(elf, SH_NOTE);
            break;
        case PT_GNU_EH_FRAME:
            elf->shdr[SH_EH_FRAME_HDR].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_EH_FRAME_HDR);
            elf->shdr[SH_EH_FRAME_HDR].sh_type = SHT_PROGBITS;
            elf->shdr[SH_EH_FRAME_HDR].sh_flags = SHF_ALLOC;
            elf->shdr[SH_EH_FRAME_HDR].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_EH_FRAME_HDR].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_EH_FRAME_HDR].sh_size = elf->phdr[i].p_filesz;
            elf->shdr[SH_EH_FRAME_HDR].sh_link = SHN_UNDEF;
            elf->shdr[SH_EH_FRAME_HDR].sh_info = 0;
            elf->shdr[SH_EH_FRAME_HDR].sh_addralign = 4;
            elf->shdr[SH_EH_FRAME_HDR].sh_entsize = 0;
            section_list_add(elf, SH_EH_FRAME_HDR);
            elf->shdr[SH_EH_FRAME].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_EH_FRAME);
            elf->shdr[SH_EH_FRAME].sh_type = SHT_PROGBITS;
            elf->shdr[SH_EH_FRAME].sh_flags = SHF_ALLOC;
            elf->shdr[SH_EH_FRAME].sh_addr = ALIGN(elf->shdr[SH_EH_FRAME_HDR].sh_addr
                                                   + elf->shdr[SH_EH_FRAME_HDR].sh_size, 8);
            elf->shdr[SH_EH_FRAME].sh_offset = ALIGN(elf->shdr[SH_EH_FRAME_HDR].sh_offset
                                                     + elf->shdr[SH_EH_FRAME_HDR].sh_size, 8);
            elf->shdr[SH_EH_FRAME].sh_link = SHN_UNDEF;
            elf->shdr[SH_EH_FRAME].sh_info = 0;
            elf->shdr[SH_EH_FRAME].sh_addralign = 8;
            elf->shdr[SH_EH_FRAME].sh_entsize = 0;
            section_list_add(elf, SH_EH_FRAME);
            break;
        default:
            break;
        }
    }
    if (!elf->dyn) {
        fprintf(stderr, "Cannot find dynamic segment");
        return false;
    }
    if (elf->rela_plt)
        ret = patch_got(elf, base);

    /* Update .text and .fini  */
    elf->shdr[SH_TEXT].sh_addr = ALIGN(elf->shdr[SH_PLT_GOT].sh_addr + elf->shdr[SH_PLT_GOT].sh_size,
                                       elf->shdr[SH_TEXT].sh_addralign);
    elf->shdr[SH_TEXT].sh_offset = elf->shdr[SH_TEXT].sh_addr;
    elf->shdr[SH_TEXT].sh_size = elf->shdr[SH_INIT].sh_addr + elf->phdr[ph_text].p_filesz
        - elf->shdr[SH_TEXT].sh_addr;
    section_list_add(elf, SH_TEXT);
    elf->shdr[SH_FINI].sh_size = elf->shdr[SH_TEXT].sh_addr + elf->shdr[SH_TEXT].sh_size
        - elf->shdr[SH_FINI].sh_addr;

    /* update .eh_frame */
    if (get_section_idx(elf, SH_RODATA) != -1) {
        elf->shdr[SH_EH_FRAME].sh_size = elf->shdr[SH_RODATA].sh_addr + elf->phdr[ph_rodata].p_filesz
            - elf->shdr[SH_EH_FRAME].sh_addr;
        /* update .rodata size */
        elf->shdr[SH_RODATA].sh_size = elf->shdr[SH_EH_FRAME_HDR].sh_addr - elf->shdr[SH_RODATA].sh_addr;
    } else {
        elf->shdr[SH_EH_FRAME].sh_size = elf->shdr[SH_TEXT].sh_addr + elf->shdr[SH_TEXT].sh_size
            - elf->shdr[SH_EH_FRAME].sh_addr;
    }

    /* add .got */
    elf->shdr[SH_GOT].sh_addr = get_got_addr(elf);
    elf->shdr[SH_GOT].sh_offset = elf->shdr[SH_GOT].sh_addr - 0x1000; /* FIXME: Find correct offset */
    elf->shdr[SH_GOT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_PLT_GOT) + 4;
    elf->shdr[SH_GOT].sh_type = SHT_PROGBITS;
    elf->shdr[SH_GOT].sh_flags = SHF_WRITE | SHF_ALLOC;
    elf->shdr[SH_GOT].sh_link = SHN_UNDEF;
    elf->shdr[SH_GOT].sh_info = 0;
    elf->shdr[SH_GOT].sh_addralign = 8;
    elf->shdr[SH_GOT].sh_entsize = 8;
    elf->shdr[SH_GOT].sh_size = GOT_SIZE(elf);
    section_list_add(elf, SH_GOT);

    /* update .data */
    if (get_section_idx(elf, SH_GOT_PLT) != -1) {
        elf->shdr[SH_DATA].sh_addr = elf->shdr[SH_GOT_PLT].sh_addr + elf->shdr[SH_GOT_PLT].sh_size;
        elf->shdr[SH_DATA].sh_offset = elf->shdr[SH_DATA].sh_addr - 0x1000; /* FIXME */
        elf->shdr[SH_DATA].sh_size = ALIGN(elf->phdr[ph_data].p_vaddr + elf->phdr[ph_data].p_filesz
                                           - elf->shdr[SH_DATA].sh_addr, elf->shdr[SH_DATA].sh_addralign);
        section_list_add(elf, SH_DATA);
    } else {
        elf->shdr[SH_DATA].sh_addr = elf->shdr[SH_GOT].sh_addr + elf->shdr[SH_GOT].sh_size;
        elf->shdr[SH_DATA].sh_offset = elf->shdr[SH_DATA].sh_addr - 0x1000; /* FIXME */
        elf->shdr[SH_DATA].sh_size = ALIGN(elf->phdr[ph_data].p_vaddr + elf->phdr[ph_data].p_filesz
                                           - elf->shdr[SH_DATA].sh_addr, elf->shdr[SH_DATA].sh_addralign);
        section_list_add(elf, SH_DATA);
    }

    /* add .bss */
    elf->shdr[SH_BSS].sh_addr = ALIGN(elf->shdr[SH_DATA].sh_addr + elf->shdr[SH_DATA].sh_size, 4);
    elf->shdr[SH_BSS].sh_offset = ALIGN(elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_DATA].sh_size, 4);
    elf->shdr[SH_BSS].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_BSS);
    elf->shdr[SH_BSS].sh_type = SHT_NOBITS;
    elf->shdr[SH_BSS].sh_flags = SHF_WRITE | SHF_ALLOC;
    elf->shdr[SH_BSS].sh_link = SHN_UNDEF;
    elf->shdr[SH_BSS].sh_info = 0;
    elf->shdr[SH_BSS].sh_addralign = 4;
    elf->shdr[SH_BSS].sh_entsize = 0;
    elf->shdr[SH_BSS].sh_size = ALIGN(elf->phdr[ph_data].p_vaddr + elf->phdr[ph_data].p_memsz
                                      - elf->shdr[SH_BSS].sh_addr, 4);
    section_list_add(elf, SH_BSS);

    /* update sh_link and sh_info */
    elf->shdr[SH_DYNAMIC].sh_link = get_section_idx(elf, SH_DYNSTR);
    elf->shdr[SH_DYNSYM].sh_link = get_section_idx(elf, SH_DYNSTR);
    elf->shdr[SH_DYNSYM].sh_info = get_idx_last_local_sym(elf);
    elf->shdr[SH_RELA_PLT].sh_link = get_section_idx(elf, SH_DYNSYM);
    elf->shdr[SH_RELA_PLT].sh_info = get_section_idx(elf, SH_GOT_PLT);
    elf->shdr[SH_HASH].sh_link = get_section_idx(elf, SH_DYNSYM);
    elf->shdr[SH_GNU_HASH].sh_link = get_section_idx(elf, SH_DYNSYM);
    elf->shdr[SH_RELA_DYN].sh_link = get_section_idx(elf, SH_DYNSYM);;
    elf->shdr[SH_VERSYM].sh_link = get_section_idx(elf, SH_DYNSYM);
    elf->shdr[SH_VERNEED].sh_link = get_section_idx(elf, SH_DYNSTR);
    return ret;
}

int main(int argc, char **argv)
{
    char path[32];
    pid_t pid = 0;
    char *core = NULL;
    int opt;
    struct elf elf;
    char *procname = NULL;
    elf_addr base_addr;

    while ((opt = getopt(argc, argv, "p:r:hv")) != -1) {
        switch (opt) {
        case 'p':
            if (strlen(optarg) > 10) {
                err_quit("Invalid process id: %s", optarg);
            }
            pid = atoi(optarg);
            break;
        case 'r':
            core = optarg;
            break;
        case 'v':
            verbose = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            exit(0);
        }
    }
    if (argc > optind)
        output_file = argv[optind];
    if (pid == 0 && !core) {
        usage(argv[0]);
        exit(0);
    }
    memset(&elf, 0, sizeof(elf));
    if (pid != 0) {
        FILE *fp;

        if ((procname = get_procname(pid)) == NULL)
            err_quit("Error getting process name");
        if (!output_file)
            output_file = procname;
        printf("[+] Reading process\n");
        if (snprintf(path, 32, "/proc/%d/maps", pid) < 0) {
            free(procname);
            err_sys("snprintf error");
        }
        if (!(fp = fopen(path, "r"))) {
            free(procname);
            err_sys("fopen error");
        }
        ptrace(PTRACE_ATTACH, pid, NULL, NULL);
        waitpid(pid, NULL, 0);
        if ((base_addr = read_process(&elf, fp, procname, pid)) == 0) {
            free(procname);
            fclose(fp);
            err_quit("Error reading process");
        }
        fclose(fp);
    } else if (core) {
        int fd;
        unsigned char *buf;
        struct stat st;

        if (!output_file)
            output_file = DEFAULT_FILE;
        if ((fd = open(core, O_RDONLY)) == -1) {
            err_sys("open error");
        }
        if (fstat(fd, &st) == -1) {
            err_sys("fstat error");
        }
        if ((buf = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0)) == MAP_FAILED)
            err_sys("mmap error");
        close(fd);
    }
    if (!parse_elf(&elf, pid, base_addr))
        goto done;
    generate_sht(&elf);
    write_file(&elf);

done:
    if (procname)
        free(procname);
    if (elf.buf)
        free(elf.buf);
    if (elf.sections.buf)
        free(elf.sections.buf);
    if (elf.shdr)
        free(elf.shdr);
    section_list_free(&elf);
}
