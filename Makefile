CLANG ?= clang
LLC ?= llc

KDIR ?= /lib/modules/$(shell uname -r)/build
ARCH ?= $(subst x86_64,x86,$(shell uname -m))

CFLAGS = \
	-Ihelpers \
	\
	-I$(KDIR)/include \
	-I$(KDIR)/include/uapi \
	-I$(KDIR)/include/generated/uapi \
	-I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/arch/$(ARCH)/include/uapi \
	-I$(KDIR)/arch/$(ARCH)/include/generated/uapi \
	-D__KERNEL__ \
	\
	-fno-stack-protector -O2 -g

xdp_%.o: xdp_%.c Makefile
	$(CLANG) -c -emit-llvm $(CFLAGS) $< -o - | \
	$(LLC) -march=bpf -filetype=obj -o $@

.PHONY: all clean

all: xdp_filter.o xdp_dummy.o

clean:
	rm -f ./*.o
