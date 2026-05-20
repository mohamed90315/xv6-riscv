#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(void)
{
  char username[16];
  char password[32];
  
  while(1) {
    printf("xv6 login: ");
    gets(username, sizeof(username));
    
    // Remove newline
    for(int i = 0; i < sizeof(username); i++) {
      if(username[i] == '\n') {
        username[i] = 0;
        break;
      }
    }
    
    printf("password: ");
    gets(password, sizeof(password));
    
    // Remove newline
    for(int i = 0; i < sizeof(password); i++) {
      if(password[i] == '\n') {
        password[i] = 0;
        break;
      }
    }
    
    if(login(username, password) == 0) {
      // Success - exec shell
      char *argv[] = { "sh", 0 };
      exec("/sh", argv);
      printf("login: exec sh failed\n");
      exit(1);
    } else {
      printf("Login failed\n");
    }
  }
  
  exit(0);
}
