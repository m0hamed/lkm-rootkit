#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main() {

  int fd_r=0,fd_w=0;
  int w_ret=100;
  fd_r = open("reader.txt", O_RDONLY);
  if(fd_r == -1)
    perror("fd_r open");

  fd_w = open("writer.txt",O_CREAT,S_IRWXU);
  if(fd_w == -1)
    perror("fd_w open");

  char *buf = (char *)malloc(50);

  printf("My process ID before calling write: %d\n", getuid());

  int n =  write(fd_w,buf, -1);

  printf("My process ID after calling write: %d\n", getuid());
  
  return 0;
}