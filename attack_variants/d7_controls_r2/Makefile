obj-m += kicba_d7_pass.o
obj-m += kicba_d7_active.o
obj-m += kicba_d7_hiding.o

KBUILD_CFLAGS += -DDEBUG=1

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

