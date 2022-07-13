BUILDDIR := build
CC := gcc
# Based on the reloc values in elf.h
ARCH = X86_64
WORD_SIZE = 64
CFLAGS += -g -std=gnu11 -Wall -DELF_ARCH=$(ARCH) -DELF_WORD_SIZE=$(WORD_SIZE)

sources = $(wildcard *.c)
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

genelf : $(objects)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(objects)

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $*.c > $(BUILDDIR)/$*.d
	@sed -i 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)

.PHONY : clean
clean :
	@rm -f genelf
	@rm -rf build

.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -

.PHONY : info
info:
	@echo "ARCH      : $(ARCH)  [options: 386 X86_64 SPARC MIPS ARM etc.]"
	@echo "WORD_SIZE : $(WORD_SIZE)"
