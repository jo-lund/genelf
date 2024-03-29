#ifndef TYPES_H
#define TYPES_H

#include <elf.h>

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define ElfN(x) CONCAT(CONCAT(CONCAT(Elf, ELF_WORD_SIZE), _), x)
#define ELFN(x) CONCAT(CONCAT(CONCAT(ELF, ELF_WORD_SIZE), _), x)
#define ELF_R_SYM ELFN(R_SYM)
#define ELF_ST_BIND ELFN(ST_BIND)
#define ELF_ST_TYPE ELFN(ST_TYPE)

typedef ElfN(Addr) elf_addr;
typedef ElfN(Ehdr) elf_ehdr;
typedef ElfN(Phdr) elf_phdr;
typedef ElfN(Shdr) elf_shdr;
typedef ElfN(Dyn) elf_dyn;
typedef ElfN(Sym) elf_sym;
typedef ElfN(Rela) elf_rela;
typedef ElfN(Rel) elf_rel;
typedef ElfN(Word) elf_word;
typedef ElfN(Xword) elf_xword;
typedef ElfN(Sxword) elf_sxword;
typedef ElfN(Off) elf_off;
typedef ElfN(Verdef) elf_verdef;
typedef ElfN(Verneed) elf_verneed;
typedef ElfN(Versym) elf_versym;
typedef ElfN(Half) elf_half;

#if ELF_WORD_SIZE == 64
#define XFMT "0x%lx"
#define AFMT "%lx"
#define UFMT "%lu"
#else
#define XFMT "0x%x"
#define AFMT "%x"
#define UFMT "%u"
#endif

#endif
