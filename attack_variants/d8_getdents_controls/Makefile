obj-m += kicba_d8_getdents_pass.o
obj-m += kicba_d8_getdents_active.o
obj-m += kicba_d8_getdents_hiding.o
obj-m += kicba_d8_getdents_policy.o

KBUILD_CFLAGS += -DDEBUG=1

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
