#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

void
test_read(char *path, char *username)
{
  int fd = open(path, O_RDONLY);
  if(fd >= 0){
    char buf[64];
    int n = read(fd, buf, sizeof(buf)-1);
    if(n < 0) n = 0;
    buf[n] = 0;
    printf("[PASS]    %s can read    %s\n", username, path);
    close(fd);
  } else {
    printf("[BLOCKED] %s cannot read  %s\n", username, path);
  }
}

void
test_write(char *path, char *username)
{
  int fd = open(path, O_WRONLY);
  if(fd >= 0){
    printf("[PASS]    %s can write   %s\n", username, path);
    close(fd);
  } else {
    printf("[BLOCKED] %s cannot write %s\n", username, path);
  }
}

int
main(void)
{
  printf("\n=== Permission Test ===\n");
  printf("Current user: ");
  whoami();
  printf("\n");

  printf("--- Read Tests ---\n");
  test_read("/device/config",      "me");
  test_read("/patient/records",    "me");
  test_read("/dosage/insulin.log", "me");
  test_read("/audit/syscall.log",  "me");

  printf("\n--- Write Tests ---\n");
  test_write("/device/config",      "me");
  test_write("/dosage/insulin.log", "me");

  printf("\n=== Done ===\n");
  exit(0);
}
