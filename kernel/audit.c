#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

#define AUDIT_SIZE 512
#define AUDIT_DESC_LEN 32

// 3.2 — Ring buffer entry
struct audit_entry {
  int pid;
  int uid;
  int trapno;
  int tick;
  char desc[AUDIT_DESC_LEN];
};

// 3.2 — Persistent kernel ring buffer
struct {
  struct spinlock lock;
  struct audit_entry entries[AUDIT_SIZE];
  int head;     // next write position
  int count;    // total entries stored (max AUDIT_SIZE)
} audit_log;

void
audit_init(void)
{
  initlock(&audit_log.lock, "audit");
  audit_log.head = 0;
  audit_log.count = 0;
}

// 3.2 — Append entry to ring buffer (overwrites oldest when full)
void
audit_log_event(int pid, int uid, int trapno, int tick, char *desc)
{
  acquire(&audit_log.lock);

  int idx = audit_log.head;
  audit_log.entries[idx].pid = pid;
  audit_log.entries[idx].uid = uid;
  audit_log.entries[idx].trapno = trapno;
  audit_log.entries[idx].tick = tick;

  // Copy description safely
  int i;
  for(i = 0; i < AUDIT_DESC_LEN - 1 && desc[i]; i++)
    audit_log.entries[idx].desc[i] = desc[i];
  audit_log.entries[idx].desc[i] = 0;

  // Advance head, wrap around (ring buffer)
  audit_log.head = (audit_log.head + 1) % AUDIT_SIZE;
  if(audit_log.count < AUDIT_SIZE)
    audit_log.count++;

  release(&audit_log.lock);
}

// 3.1 — Map trap number to human-readable name
char*
trap_name(int trapno)
{
  switch(trapno){
    case 8:  return "SYSCALL";
    case 12: return "PAGEFAULT_INST";
    case 13: return "PAGEFAULT_LOAD";
    case 15: return "PAGEFAULT_STORE";
    case 5:  return "TIMER";
    case 9:  return "S_EXT_INTR";
    default: return "UNKNOWN";
  }
}

// 3.3 — Root-only reader
// Returns number of entries copied, or -1 (EPERM) if not admin
uint64
sys_audit_read(void)
{
  uint64 buf;
  int n;
  struct proc *p = myproc();

  // 3.3 — Only uid=0 (admin) may read the audit log
  if(p->uid != 0)
    return -1;  // EPERM

  argaddr(0, &buf);
  argint(1, &n);

  if(n <= 0)
    return 0;
  if(n > AUDIT_SIZE)
    n = AUDIT_SIZE;
  if(n > audit_log.count)
    n = audit_log.count;

  acquire(&audit_log.lock);

  // Calculate starting index (oldest entry)
  int start;
  if(audit_log.count < AUDIT_SIZE)
    start = 0;
  else
    start = audit_log.head;  // oldest entry

  // Copy entries to user space
  for(int i = 0; i < n; i++){
    int idx = (start + i) % AUDIT_SIZE;
    if(copyout(p->pagetable, buf + i * sizeof(struct audit_entry),
               (char*)&audit_log.entries[idx],
               sizeof(struct audit_entry)) < 0){
      release(&audit_log.lock);
      return -1;
    }
  }

  release(&audit_log.lock);
  return n;
}
