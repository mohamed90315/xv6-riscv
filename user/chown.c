#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  int uid;

  if(argc != 3){
    fprintf(2, "usage: chown uid file\n");
    exit(1);
  }

  uid = atoi(argv[1]);

  if(chown(argv[2], uid) < 0){
    fprintf(2, "chown failed\n");
    exit(1);
  }

  exit(0);
}
