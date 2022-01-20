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

#define IS_POWEROF2(x) ((x) > 0 && ((x) & (x - 1)) == 0)
#define GOT_NELEMS(elf) ((elf)->shdr[SH_RELA_PLT].sh_size / sizeof(elf_rela))
#define GOT_NRESERVED_ELEMS 3

enum section_id {
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
    SH_HASH,
    SH_GNU_HASH,
    SH_SHSTRTAB,
    NUM_SECTIONS
};

struct string_table {
    enum section_id id;
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
    { SH_HASH, ".hash", 5 },
    { SH_GNU_HASH, ".gnu.hash", 9 },
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

static bool valid_hash = false;
static bool valid_gnu_hash = false;
static bool verbose = false;
static char *output_file = NULL;

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

static int get_section_index(struct elf *elf, int section_id)
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
        if (i == sid)
            return idx;
        idx += tbl[i].len + 1;
    }
    return -1;
}

static elf_addr get_plt_addr(elf_addr init_addr)
{
    /*
     * TODO: search for the first entry
     *
     * .PLT0: push  DWORD PTR [ebx + 4]
     *        jmp   [ebx + 8]
     *        nop
     */
    elf_addr addr = init_addr + 0x1a;

    return addr + (-addr & 0xf); /* align on a 16 byte boundary */
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

void generate_sht(struct elf *elf)
{
    size_t offset;
    unsigned int sh_strsize = 0;
    unsigned int shstrtab_elems = ARRAY_SIZE(shstrtab);
    struct slist *n;
    int c = 0;

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
    elf->shdr[SH_SHSTRTAB].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_SHSTRTAB);
    elf->shdr[SH_SHSTRTAB].sh_type = SHT_STRTAB;
    elf->shdr[SH_SHSTRTAB].sh_flags = 0;
    elf->shdr[SH_SHSTRTAB].sh_addr = 0;
    elf->shdr[SH_SHSTRTAB].sh_offset = elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_DATA].sh_size;
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
    unsigned char *buf;
    elf_ehdr *ehdr;
    elf_phdr *phdr;

    offset = 0;
    while (fgets(line, BUFSIZE, fp)) {
        if (sscanf(line, "%lx-%lx %*s %*x %*s %*d %s", &from, &to, path) < 3)
            continue;
        if (strstr(path, name) != NULL)
            break;
    }
    buf = xmalloc(to - from);
    if (mem_read(pid, buf, (void *) from, to - from) == -1) {
        free(buf);
        return 0;
    }
    if (buf[EI_MAG0] != 0x7f || buf[EI_MAG1] != 'E' ||
        buf[EI_MAG2] != 'L' || buf[EI_MAG3] != 'F') {
        err_msg("Not an ELF executable\n");
        free(buf);
        return 0;
    }
    ehdr = (elf_ehdr *) buf;
    phdr = (elf_phdr *) (buf + ehdr->e_phoff);

    /* get the size of the loadable segments */
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset > elf->size)
                elf->size = phdr[i].p_offset;
            elf->size += phdr[i].p_filesz;
        }
    }

    /* read the loadable segments */
    elf->buf = xmalloc(elf->size);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset > offset)
                offset = phdr[i].p_offset;
            if (mem_read(pid, elf->buf + offset, (void *) (from + phdr[i].p_vaddr),
                         phdr[i].p_filesz) == -1) {
                free(buf);
                return 0;
            }
        }
    }
    free(buf);
    return from;
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

static void read_dynamic_segment(struct elf *elf, elf_addr base)
{
    elf_word *hashtab;

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
            elf->shdr[SH_DYNSYM].sh_info = 0; // ??
            elf->shdr[SH_DYNSYM].sh_addralign = 8;
            section_list_add(elf, SH_DYNSYM);
            break;
        case DT_SYMENT:
            elf->shdr[SH_DYNSYM].sh_entsize = elf->dyn[i].d_un.d_val;
            break;
        case DT_JMPREL: /* .rela.plt section */
            elf->shdr[SH_RELA_PLT].sh_offset = elf->dyn[i].d_un.d_ptr - base;
            elf->rela = (elf_rela *) (elf->buf + elf->dyn[i].d_un.d_ptr - base);
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            elf->shdr[SH_RELA_PLT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_RELA_PLT);
            elf->shdr[SH_RELA_PLT].sh_type = SHT_RELA;
            elf->shdr[SH_RELA_PLT].sh_flags = SHF_ALLOC | SHF_INFO_LINK;
            elf->shdr[SH_RELA_PLT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_RELA_PLT].sh_addralign = 8;
            elf->shdr[SH_RELA_PLT].sh_entsize = 0x18; // Same as .dynsym?
            section_list_add(elf, SH_RELA_PLT);
            break;
        case DT_PLTRELSZ: /* size of the .rela.plt section */
            elf->shdr[SH_RELA_PLT].sh_size = elf->dyn[i].d_un.d_val;
            break;
        case DT_INIT: /* .init section */
            elf->shdr[SH_INIT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_INIT);
            elf->shdr[SH_INIT].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INIT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
            elf->shdr[SH_INIT].sh_addr = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_offset = elf->dyn[i].d_un.d_ptr;
            elf->shdr[SH_INIT].sh_size = 0; // ??
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
        case DT_RELA: /* TODO: add support for more sections */
        case DT_REL:
        case DT_VERSYM:
            UPDATE_ADDRESS(elf, elf->dyn[i].d_un.d_ptr, base);
            break;
        default:
            break;
        }
    }
}

static void patch_got(struct elf *elf, elf_addr base)
{
    elf_addr plt_addr;
    elf_addr plt_entry;
    elf_addr got_entry;

    /*
     * Set the size of .got.plt based on the size of the .rela.plt relocation table,
     * which holds information to relocate entries in the .got.plt section.
     */
    elf->shdr[SH_GOT_PLT].sh_size = (GOT_NELEMS(elf) + GOT_NRESERVED_ELEMS) * sizeof(elf_addr);

    /* set the offset based on the data offset and the address of the GOT entry */
    elf->shdr[SH_GOT_PLT].sh_offset = elf->shdr[SH_DATA].sh_offset + elf->rela[0].r_offset -
        elf->shdr[SH_DATA].sh_addr - GOT_NRESERVED_ELEMS * sizeof(elf_addr);

    plt_addr = get_plt_addr(elf->shdr[SH_INIT].sh_addr);

    /* clear GOT[1] and GOT[2] */
    memset(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           8 - elf->shdr[SH_DATA].sh_addr, 0, sizeof(elf_addr));
    memset(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->shdr[SH_GOT_PLT].sh_addr +
           16 - elf->shdr[SH_DATA].sh_addr, 0, sizeof(elf_addr));

    /* r_offset contains the virtual address for the specific GOT entries */
    for (int i = 0; i < GOT_NELEMS(elf); i++) {
        int sym_idx = ELF_R_SYM(elf->rela[i].r_info); /* symbol table index */

        /* 6 is the size of the first instruction in PLT[n] (jmp   [ebx + name1@GOT]) */
        /* 16 is the size of a PLT entry */
        plt_entry = plt_addr + (i + 1) * 16 + 6;
        got_entry = *((elf_addr *) (elf->buf + elf->shdr[SH_DATA].sh_offset +
                                    elf->rela[i].r_offset - elf->shdr[SH_DATA].sh_addr));
        UPDATE_ADDRESS(elf, got_entry, base);
        if (plt_entry != got_entry) {
            memcpy(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->rela[i].r_offset -
                   elf->shdr[SH_DATA].sh_addr, &plt_entry, sizeof(elf_addr));
            printf("[+] Patching got[%d]:\n", i + 3);
            printf("    0x%lx\t0x%lx\t0x%lx\t%s\n",
                   elf->rela[i].r_offset, /* address of GOT entry */
                   elf->rela[i].r_info, /* symbol table index and type of relocation */
                   *((elf_addr *) (elf->buf + elf->shdr[SH_DATA].sh_offset +
                                   elf->rela[i].r_offset - elf->shdr[SH_DATA].sh_addr)),
                   elf->dynstr + elf->sym[sym_idx].st_name); /* name in the string table */
        } else if (elf->ehdr->e_type == ET_DYN) {
            /* update got to the relative address for pies */
            memcpy(elf->buf + elf->shdr[SH_DATA].sh_offset + elf->rela[i].r_offset -
                   elf->shdr[SH_DATA].sh_addr, &got_entry, sizeof(elf_addr));
        }
    }
}

static bool parse_elf(struct elf *elf, pid_t pid, elf_addr base)
{
    elf->ehdr = (elf_ehdr *) elf->buf;
    elf->phdr = (elf_phdr *) (elf->buf + elf->ehdr->e_phoff);
    elf->shdr = xcalloc(NUM_SECTIONS, sizeof(*elf->shdr));
    elf->section_list = calloc(1, sizeof(*elf->section_list));
    elf->section_list->shdr = &elf->shdr[SH_NULL];
    elf->section_list->id = SH_NULL;
    if (elf->ehdr->e_type != ET_EXEC && elf->ehdr->e_type != ET_DYN) {
        fprintf(stderr, "ELF type not supported: %d", elf->ehdr->e_type);
        return false;
    }
    for (int i = 0; i < elf->ehdr->e_phnum; i++) {
        switch (elf->phdr[i].p_type) {
        case PT_LOAD:
            if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_W)) {
                printf("    Data segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                elf->shdr[SH_DATA].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_DATA);
                elf->shdr[SH_DATA].sh_type = SHT_PROGBITS;
                elf->shdr[SH_DATA].sh_flags = SHF_WRITE | SHF_ALLOC;
                elf->shdr[SH_DATA].sh_addr = elf->phdr[i].p_vaddr;
                elf->shdr[SH_DATA].sh_offset = elf->phdr[i].p_offset;
                elf->shdr[SH_DATA].sh_size = elf->phdr[i].p_filesz;
                elf->shdr[SH_DATA].sh_link = SHN_UNDEF;
                elf->shdr[SH_DATA].sh_info = 0;
                elf->shdr[SH_DATA].sh_addralign = elf->phdr[i].p_align;
                elf->shdr[SH_DATA].sh_entsize = 0;
                section_list_add(elf, SH_DATA);
            } else if (elf->phdr[i].p_offset && elf->phdr[i].p_flags == (PF_R | PF_X)) {
                printf("    Text segment: 0x%lx - 0x%lx (off: %lu, size: %lu bytes)\n",
                       elf->phdr[i].p_vaddr, elf->phdr[i].p_vaddr + elf->phdr[i].p_filesz,
                       elf->phdr[i].p_offset, elf->phdr[i].p_filesz);
                elf->shdr[SH_TEXT].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_TEXT);
                elf->shdr[SH_TEXT].sh_type = SHT_PROGBITS;
                elf->shdr[SH_TEXT].sh_flags = SHF_EXECINSTR | SHF_ALLOC;
                elf->shdr[SH_TEXT].sh_addr = elf->phdr[i].p_vaddr;
                elf->shdr[SH_TEXT].sh_offset = elf->phdr[i].p_offset;
                elf->shdr[SH_TEXT].sh_size = elf->phdr[i].p_filesz;
                elf->shdr[SH_TEXT].sh_link = SHN_UNDEF;
                elf->shdr[SH_TEXT].sh_info = 0;
                elf->shdr[SH_TEXT].sh_addralign = elf->phdr[i].p_align;
                elf->shdr[SH_TEXT].sh_entsize = 0;
                section_list_add(elf, SH_TEXT);
            }
            break;
        case PT_INTERP:
            elf->shdr[SH_INTERP].sh_name = get_strtbl_idx(shstrtab, ARRAY_SIZE(shstrtab), SH_INTERP);
            elf->shdr[SH_INTERP].sh_type = SHT_PROGBITS;
            elf->shdr[SH_INTERP].sh_flags = SHF_ALLOC;
            elf->shdr[SH_INTERP].sh_addr = elf->phdr[i].p_vaddr;
            elf->shdr[SH_INTERP].sh_offset = elf->phdr[i].p_offset;
            elf->shdr[SH_INTERP].sh_size = elf->phdr[i].p_memsz;
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
            elf->shdr[SH_DYNAMIC].sh_size = elf->phdr[i].p_memsz;
            elf->shdr[SH_DYNAMIC].sh_info = 0;
            elf->shdr[SH_DYNAMIC].sh_addralign = elf->phdr[i].p_align;
            elf->shdr[SH_DYNAMIC].sh_entsize = 0;
            section_list_add(elf, SH_DYNAMIC);
            read_dynamic_segment(elf, base);
            elf->shdr[SH_DYNSYM].sh_size = get_nsymbols(elf) * elf->shdr[SH_DYNSYM].sh_entsize;

            /* update sh_link and sh_info */
            elf->shdr[SH_DYNAMIC].sh_link = get_section_index(elf, SH_DYNSTR);
            elf->shdr[SH_DYNSYM].sh_link = get_section_index(elf, SH_DYNSTR);
            elf->shdr[SH_RELA_PLT].sh_link = get_section_index(elf, SH_DYNSYM);
            elf->shdr[SH_RELA_PLT].sh_info = get_section_index(elf, SH_GOT_PLT);
            elf->shdr[SH_HASH].sh_link = get_section_index(elf, SH_DYNSYM);
            elf->shdr[SH_GNU_HASH].sh_link = get_section_index(elf, SH_DYNSYM);
        default:
            break;
        }
    }
    if (!elf->dyn) {
        fprintf(stderr, "Cannot find dynamic segment");
        return false;
    }
    if (elf->rela)
        patch_got(elf, base);
    return true;
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
            printf("verbose\n");
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
