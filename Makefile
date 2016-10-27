ifneq ($(KERNELRELEASE),)
	EXTRA_CFLAGS := -I$(src)/arch/x86/include
	sgx-y := \
		sgx_main.o \
		sgx_page_cache.o \
		sgx_ioctl.o \
		sgx_vma.o \
		sgx_util.o
	obj-m += sgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
