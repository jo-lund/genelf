#ifndef MACHDEP_H
#define MACHDEP_H

#include <stddef.h>
#include "types.h"

struct elf;

size_t get_plt0_size(void);

/* get the address of the .plt section */
elf_addr get_plt_addr(struct elf *elf);

/* get the address of the .got section */
elf_addr get_got_addr(struct elf *elf);

#endif
