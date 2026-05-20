#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  if(argc != 2){
    printf("Usage: userdel <username>\n");
    exit(1);
  }

  if(userdel(argv[1]) == 0){
    printf("User '%s' deleted successfully\n", argv[1]);
  } else {
    printf("userdel failed (not admin or user not found)\n");
  }

  exit(0);
}
