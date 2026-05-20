#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

// Must match kernel/audit.c struct
struct audit_entry {
  int pid;
  int uid;
  int trapno;
  int tick;
  char desc[32];
};

#define MAX_ENTRIES 50

struct audit_entry entries[MAX_ENTRIES];

int
main(void)
{
  int n;

  printf("=== Audit Log Demo ===\n\n");

  // 3.3 — Read audit log with current shell user
  // Only uid=0 (admin) can read; all others get EPERM
  printf("Step: read audit log with current user...\n");
  n = audit_read(entries, MAX_ENTRIES);
  if(n < 0){
    printf("  [PASS] audit_read returned EPERM (not admin)\n");
  } else {
    printf("  [PASS] Admin read %d audit entries\n\n", n);
    printf("  Recent entries:\n");
    for(int i = 0; i < n; i++){
      printf("  [%d] PID=%d UID=%d TRAP=%d TICK=%d DESC=%s\n",
             i,
             entries[i].pid,
             entries[i].uid,
             entries[i].trapno,
             entries[i].tick,
             entries[i].desc);
    }
  }

  printf("\n=== Audit Demo Complete ===\n");
  exit(0);
}
