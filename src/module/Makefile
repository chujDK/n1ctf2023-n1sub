obj-m+=sub.o 
 
PWD:=$(CURDIR) 
KERNEL_SRC=/PATH/TO/linux-6.1.58

all:
	make -C $(KERNEL_SRC) M=$(PWD) modules

clean:
	make -C $(KERNEL_SRC) M=$(PWD) clean
