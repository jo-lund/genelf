#include <string.h>
#include "machdep.h"
#include "genelf.h"

static const uint8_t plt_pattern[] = {
    0xff, 0xb3, 0x04, 0x00, 0x00, 0x00, /* push DWORD PTR [ebx+0x4] */ \
    0xff, 0xa3, 0x08, 0x00, 0x00, 0x00, /* jmp  DWORD PTR [ebx+0x8] */ \
    0x00, 0x00
};

size_t get_plt0_size(void)
{
    return sizeof(plt_pattern);
}

elf_addr get_plt_addr(struct elf *elf)
{
    for (elf_addr i = elf->shdr[SH_INIT].sh_offset; i < elf->phdr[ph_text].p_offset +
             elf->phdr[ph_text].p_filesz - 12; i++) {
        if (memcmp(&elf->buf[i], &plt_pattern[0], 3) == 0 &&
            memcmp(&elf->buf[i + 6], &plt_pattern[6], 3) == 0)
            return elf->ehdr->e_type == ET_EXEC ? i + elf->base : i;
    }
    return -1;
}

elf_addr get_got_addr(struct elf *elf)
{
    for (int i = 0; i < GOT_NELEMS(elf); i++) {
        if (ELF_ST_TYPE(GET_REL(elf, dyn, info, i)) == R_386_GLOB_DAT)
            return GET_REL(elf, dyn, offset, i);
    }
    return 0;
}
