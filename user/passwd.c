#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 3){
    printf("Usage: passwd <username> <newpassword>\n");
    exit(1);
  }

  if(passwd(argv[1], argv[2]) == 0){
    printf("Password changed successfully\n");
  } else {
    printf("passwd failed\n");
  }

  exit(0);
}
