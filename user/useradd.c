#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 5){
    printf("Usage: useradd <username> <uid> <gid> <password>\n");
    exit(1);
  }

  int uid = atoi(argv[2]);
  int gid = atoi(argv[3]);

  if(useradd(argv[1], uid, gid, argv[4]) == 0){
    printf("User '%s' added successfully\n", argv[1]);
  } else {
    printf("useradd failed (not admin or user exists)\n");
  }

  exit(0);
}
