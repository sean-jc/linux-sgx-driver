ifneq ($(KERNELRELEASE),)
	EXTRA_CFLAGS := -I$(src)
	isgx-y := \
		intel_sgx_main.o \
		intel_sgx_page_cache.o \
		intel_sgx_ioctl.o \
		intel_sgx_vma.o \
		intel_sgx_util.o
	obj-m += isgx.o
else
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) CFLAGS_MODULE="-DDEBUG -g -O0" modules

install: default
	$(MAKE) INSTALL_MOD_DIR=kernel/drivers/intel/sgx -C $(KDIR) M=$(PWD) modules_install
	sh -c "cat /etc/modules | grep -Fxq isgx || echo isgx >> /etc/modules"

endif

clean:
	rm -vrf *.o *.ko *.order *.symvers *.mod.c .tmp_versions .*o.cmd
