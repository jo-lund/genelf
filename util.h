#include <stdlib.h>

#define ELF_WORD_SIZE 64
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define ElfN(x) CONCAT(CONCAT(CONCAT(Elf, ELF_WORD_SIZE), _), x)
#define ELFN(x) CONCAT(CONCAT(CONCAT(ELF, ELF_WORD_SIZE), _), x)
#define ELF_R_SYM ELFN(R_SYM)

typedef ElfN(Addr) elf_addr;
typedef ElfN(Ehdr) elf_ehdr;
typedef ElfN(Phdr) elf_phdr;
typedef ElfN(Shdr) elf_shdr;
typedef ElfN(Dyn) elf_dyn;
typedef ElfN(Sym) elf_sym;
typedef ElfN(Rela) elf_rela;
typedef ElfN(Xword) elf_xword;
typedef ElfN(Off) elf_off;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static inline void *xmalloc(size_t size)
{
    void *p;

    if ((p = malloc(size)) == NULL)
        exit(0);
    return p;
}

static inline void *xcalloc(size_t nmemb, size_t size)
{
    void *p;

    if ((p = calloc(nmemb, size)) == NULL)
        exit(0);
    return p;
}

static inline void *xrealloc(void *ptr, size_t size)
{
    if ((ptr = realloc(ptr, size)) == NULL)
        exit(0);
    return ptr;
}


static inline bool is_elf(unsigned char *buf)
{
    return memcmp(buf, ELFMAG, SELFMAG);
}
