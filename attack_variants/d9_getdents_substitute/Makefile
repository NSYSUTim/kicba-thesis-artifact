obj-m += kicba_d9_getdents_substitute.o

KBUILD_CFLAGS += -DDEBUG=1

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
