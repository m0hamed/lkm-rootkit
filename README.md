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

----------------------------------------------------------------------
