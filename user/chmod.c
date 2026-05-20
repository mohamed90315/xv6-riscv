#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  int mode = 0;
  char *s;

  if(argc != 3){
    fprintf(2, "usage: chmod mode file\n");
    exit(1);
  }

  s = argv[1];
  while(*s >= '0' && *s <= '7'){
    mode = mode * 8 + (*s - '0');
    s++;
  }

  if(chmod(argv[2], mode) < 0){
    fprintf(2, "chmod failed\n");
    exit(1);
  }

  exit(0);
}
