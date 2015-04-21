obj-m   := rootkit.o
 
KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)
#ccflags-y := -fomit-frame-pointer

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
