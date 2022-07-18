#ifndef GENELF_H
#define GENELF_H

#include "slist.h"
#include "types.h"

#define GOT_NELEMS(elf) \
    ((elf)->reldyn_type == DT_RELA ? \
     ((elf)->shdr[SH_RELA_DYN].sh_size / (elf)->shdr[SH_RELA_DYN].sh_entsize) : \
     ((elf)->shdr[SH_REL_DYN].sh_size / (elf)->shdr[SH_REL_DYN].sh_entsize))
#define GOT_SIZE(elf) (GOT_NELEMS(elf) * 8)

/*
 * Use the correct relocation structure and return the value of the member at the given index.
 * t: type (plt or dyn)
 * m: elf_rela/elf_rel struct member (without 'r_' prefix)
 * i: index
*/
#define GET_REL(elf, t, m, i)                          \
    ((elf)->CONCAT(CONCAT(rel, t), _type) == DT_RELA ? \
     CONCAT((elf)->rela_, t)[i].CONCAT(r_, m) :        \
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

struct elf {
    elf_ehdr *ehdr;
    elf_phdr *phdr;
    elf_shdr *shdr;
    elf_dyn *dyn;
    elf_sym *sym;
    elf_addr base;
    union {
        elf_rela *rela_plt;
        elf_rel *rel_plt;
    };
    elf_sxword relplt_type;
    union {
        elf_rela *rela_dyn;
        elf_rel *rel_dyn;
    };
    elf_sxword reldyn_type;
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

extern int ph_data;
extern int ph_text;
extern int ph_rodata;

#endif
