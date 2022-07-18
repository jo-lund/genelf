#include <string.h>
#include "machdep.h"
#include "genelf.h"

/*
 * Push and jmp use 1 byte opcodes and modR/M byte, nop uses two bytes opcode
 * and modR/M byte
 */
static const uint8_t plt_pattern[] = {
    0xff, 0x35, 0x00, 0x00, 0x00, 0x00, /* push <indirect address> */ \
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00, /* jmp <indirect address> */  \
    0x0f, 0x1f, 0x40, 0x00              /* nop */

};

size_t get_plt0_size(void)
{
    return sizeof(plt_pattern);
}

elf_addr get_plt_addr(struct elf *elf)
{
    for (elf_addr i = elf->shdr[SH_INIT].sh_offset; i < elf->phdr[ph_text].p_offset +
             elf->phdr[ph_text].p_filesz - 16; i++) {
        if (memcmp(&elf->buf[i], &plt_pattern[0], 2) == 0 &&
            memcmp(&elf->buf[i + 6], &plt_pattern[6], 2) == 0 &&
            memcmp(&elf->buf[i + 12], &plt_pattern[12], 3) == 0)
            return elf->ehdr->e_type == ET_EXEC ? i + elf->base : i;
    }
    return -1;
}

elf_addr get_got_addr(struct elf *elf)
{
    for (int i = 0; i < GOT_NELEMS(elf); i++) {
        if (ELF_ST_TYPE(GET_REL(elf, dyn, info, i)) == R_X86_64_GLOB_DAT)
            return GET_REL(elf, dyn, offset, i);
    }
    return 0;
}
