BUILDDIR := build
STRIP := strip
PREFIX := /usr/local
CC := gcc
ARCH = X86_64
WORD_SIZE = 64
CFLAGS += -g -std=gnu11 -Wall -DELF_ARCH=$(ARCH) -DELF_WORD_SIZE=$(WORD_SIZE)
CPPFLAGS += -I $(CURDIR)
sources = $(wildcard *.c)
ifeq ($(ARCH),X86_64)
ifeq ($(WORD_SIZE),32)
	sources += $(wildcard i386/*.c)
else
	sources += $(wildcard x86_64/*.c)

endif
endif
ifeq ($(ARCH),386)
	WORD_SIZE = 32
	sources += $(wildcard i386/*.c)
endif
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

genelf : $(objects)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(objects)

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $(CPPFLAGS) $*.c > $(BUILDDIR)/$*.d
	@sed -i 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)

install :
	@install -sD --strip-program=$(STRIP) genelf $(PREFIX)/bin/genelf

.PHONY : clean
clean :
	@rm -f genelf
	@rm -rf build

.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -

.PHONY : info
info:
	@echo "ARCH      : $(ARCH)  [options: 386 X86_64]"
	@echo "WORD_SIZE : $(WORD_SIZE)"
