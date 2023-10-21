# Task 1.A Implementaing a simplem kernel module
This tasks's main objective is to see how Loadable Kernel Module (LKM) work in linux with a simple `Hellow World` program

## compile the module

In the `Makefile` 
```
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
```
This line builds the kernel and outputs `hello.ko` file which is a LKM that can be loaded into the linux kernel
Simpily run `make` in the same directory as the `Makefile`
You will get the following output 
```
seed@weihong-System-Product-Name:~/Desktop/networksecurtiy_lab/firewall/Files/kernel_module$ make
make -C /lib/modules/5.15.0-86-generic/build M=/home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module modules
make[1]: Entering directory '/usr/src/linux-headers-5.15.0-86-generic'
  CC [M]  /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/hello.o
  MODPOST /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/Module.symvers
  CC [M]  /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/hello.mod.o
  LD [M]  /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/hello.ko
  BTF [M] /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/hello.ko
Skipping BTF generation for /home/seed/Desktop/networksecurtiy_lab/firewall/Files/kernel_module/hello.ko due to unavailability of vmlinux
make[1]: Leaving directory '/usr/src/linux-headers-5.15.0-86-generic'
```
In the same folder as the `Makefile` there are several files being created
```
hello.ko
hello.mod
hello.mode.c
hello.mode.o
hello.o
modules.order
```

## Insert the module
Run `sudo insmod hello.ko`
There should not be any output seen in the terminal

## List modules

Run `sudo lsmod|grep hello`
This command list the modules and pipe it into `grep` program and filter for `hello`

### output
```
seed@weihong-System-Product-Name:~/Desktop/networksecurtiy_lab/firewall/Files/kernel_module$ lsmod | grep hello
hello                  16384  0
```

From the output we see that the kernel module is successfully loaded

## Remove the module
Run `sudo rmmod hello`

## Output message
Run `dmesg`
We can see the following two lines that is printed out by out kernel module
```
[20371.495459] Hello World!
[20662.363058] Bye-bye World!.
```
Which means that kernel execution is successful
