NOTICE:This kernel module is only compatible with 64-bit PCs. Please do NOT run if your PC is a 32-bit.

To compile the module:
make -f Makefile

To load the module in kernel:
sudo insmod rootkit.ko

To remove the module from kernel:
sudo rmmod rootkit

To check whether the module is loaded:
lsmod | grep rootkit

To view kernel printed msgs:
dmesg | tail

To hide a certain PID:
echo "hide_proc <pid>" > /proc/rootkitproc

To unhide a certain PID:
echo "show_proc <pid>" > /proc/rootkitproc
