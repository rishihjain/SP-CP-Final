ifeq ($(KERNELRELEASE),)

KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD        = $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	rm -rf *~ core .depend .*.cmd *.mod.c .tmp_versions *.mod modules.order *.symvers

fclean: clean
	rm -rf *.ko *.o

re: clean all

else
    obj-m = linux_driver.o

endif