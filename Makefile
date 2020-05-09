CONFIG_MODULE_SIG=n
obj-m := hook_idt.o
KERNELBUILD :=/lib/modules/$(shell uname -r)/build
default:
	make -C $(KERNELBUILD) M=$(shell pwd) modules
clean:
	rm -rf *.o *.mod.c *.mod.o .*.cmd .tmp_versions *.order *.symvers
