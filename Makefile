obj-m := datto-agent.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
EXTRA_CFLAGS := -g
default:
	$(MAKE) -I/usr/include -C $(KDIR) SUBDIRS=$(PWD) modules

clean:
	$(MAKE) -I/usr/include -C $(KDIR) SUBDIRS=$(PWD) clean

insmod: default
	insmod datto-agent.ko
	
mount:
	mount -o ro,noexec,noload /dev/datto /mnt/datto/
	
umount:
	umount /dev/datto
	
rmmod:
	rmmod datto_agent
