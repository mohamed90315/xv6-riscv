#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "syscall.h"

struct spinlock tickslock;
uint ticks;

extern char trampoline[], uservec[];

// in kernelvec.S, calls kerneltrap().
void kernelvec();

extern int devintr();

void
trapinit(void)
{
  initlock(&tickslock, "time");
}

// set up to take exceptions and traps while in the kernel.
void
trapinithart(void)
{
  w_stvec((uint64)kernelvec);
}

// ============================================================
// 3.1 — Map trap number to human-readable name
// ============================================================
static char*
get_trap_name(uint64 scause)
{
  switch(scause){
    case 8:  return "SYSCALL";
    case 12: return "PAGEFAULT_INST";
    case 13: return "PAGEFAULT_LOAD";
    case 15: return "PAGEFAULT_STORE";
    case 2:  return "ILLEGAL_INST";
    case 3:  return "BREAKPOINT";
    case 5:  return "LOAD_MISALIGN";
    case 7:  return "STORE_MISALIGN";
    default: return "UNKNOWN";
  }
}

// ============================================================
// 3.1 — Map syscall number to human-readable name
// ============================================================
static char*
get_syscall_name(int sysnum)
{
  switch(sysnum){
    case SYS_fork:       return "fork";
    case SYS_exit:       return "exit";
    case SYS_wait:       return "wait";
    case SYS_pipe:       return "pipe";
    case SYS_read:       return "read";
    case SYS_kill:       return "kill";
    case SYS_exec:       return "exec";
    case SYS_fstat:      return "fstat";
    case SYS_chdir:      return "chdir";
    case SYS_dup:        return "dup";
    case SYS_getpid:     return "getpid";
    case SYS_sbrk:       return "sbrk";
    case SYS_pause:      return "pause";
    case SYS_uptime:     return "uptime";
    case SYS_open:       return "open";
    case SYS_write:      return "write";
    case SYS_mknod:      return "mknod";
    case SYS_unlink:     return "unlink";
    case SYS_link:       return "link";
    case SYS_mkdir:      return "mkdir";
    case SYS_close:      return "close";
    case SYS_useradd:    return "useradd";
    case SYS_userdel:    return "userdel";
    case SYS_passwd:     return "passwd";
    case SYS_whoami:     return "whoami";
    case SYS_login:      return "login";
    case SYS_chmod:      return "chmod";
    case SYS_chown:      return "chown";
    case SYS_audit_read: return "audit_read";
    default:             return "unknown";
  }
}

// ============================================================
// 3.1 — Should we print this syscall to console?
// Skip high-frequency noisy syscalls
// ============================================================
static int
should_print_syscall(int sysnum)
{
  switch(sysnum){
    case SYS_write:   return 0; // too noisy
    case SYS_read:    return 0; // too noisy
    case SYS_uptime:  return 0; // too noisy
    case SYS_pause:   return 0; // too noisy
    default:          return 1; // print everything else
  }
}

//
// handle an interrupt, exception, or system call from user space.
// called from, and returns to, trampoline.S
// return value is user satp for trampoline.S to switch to.
//
uint64
usertrap(void)
{
  int which_dev = 0;

  if((r_sstatus() & SSTATUS_SPP) != 0)
    panic("usertrap: not from user mode");

  w_stvec((uint64)kernelvec);

  struct proc *p = myproc();
  
  p->trapframe->epc = r_sepc();
  
  if(r_scause() == 8){
    // system call

    if(killed(p))
      kexit(-1);

    p->trapframe->epc += 4;

    intr_on();

    int sysnum = p->trapframe->a7;

    // ✅ 3.2 — Always log ALL syscalls to ring buffer
    audit_log_event(p->pid, p->uid, sysnum, ticks,
                    get_syscall_name(sysnum));

    // ✅ 3.1 — Pretty print important syscalls to console
    if(should_print_syscall(sysnum)){
      printf("[AUDIT] PID=%d UID=%d TRAP=SYSCALL(%s) EIP=%lx\n",
             p->pid,
             p->uid,
             get_syscall_name(sysnum),
             p->trapframe->epc);
    }

    syscall();

  } else if((which_dev = devintr()) != 0){
    // ok
  } else if((r_scause() == 15 || r_scause() == 13) &&
            vmfault(p->pagetable, r_stval(), (r_scause() == 13)? 1 : 0) != 0) {
    // page fault on lazily-allocated page

  } else {
    // ✅ 3.1 — Pretty print other traps to console
    printf("[AUDIT] PID=%d UID=%d TRAP=%s EIP=%lx\n",
           p->pid,
           p->uid,
           get_trap_name(r_scause()),
           r_sepc());

    // ✅ 3.2 — Log other traps to ring buffer
    audit_log_event(p->pid, p->uid, (int)r_scause(),
                    ticks, get_trap_name(r_scause()));

    printf("usertrap(): unexpected scause 0x%lx pid=%d\n", r_scause(), p->pid);
    printf("            sepc=0x%lx stval=0x%lx\n", r_sepc(), r_stval());
    setkilled(p);
  }

  if(killed(p))
    kexit(-1);

  if(which_dev == 2)
    yield();

  prepare_return();

  uint64 satp = MAKE_SATP(p->pagetable);

  return satp;
}

//
// set up trapframe and control registers for a return to user space
//
void
prepare_return(void)
{
  struct proc *p = myproc();

  intr_off();

  uint64 trampoline_uservec = TRAMPOLINE + (uservec - trampoline);
  w_stvec(trampoline_uservec);

  p->trapframe->kernel_satp = r_satp();
  p->trapframe->kernel_sp = p->kstack + PGSIZE;
  p->trapframe->kernel_trap = (uint64)usertrap;
  p->trapframe->kernel_hartid = r_tp();

  unsigned long x = r_sstatus();
  x &= ~SSTATUS_SPP;
  x |= SSTATUS_SPIE;
  w_sstatus(x);

  w_sepc(p->trapframe->epc);
}

// interrupts and exceptions from kernel code go here via kernelvec,
// on whatever the current kernel stack is.
void 
kerneltrap()
{
  int which_dev = 0;
  uint64 sepc = r_sepc();
  uint64 sstatus = r_sstatus();
  uint64 scause = r_scause();
  
  if((sstatus & SSTATUS_SPP) == 0)
    panic("kerneltrap: not from supervisor mode");
  if(intr_get() != 0)
    panic("kerneltrap: interrupts enabled");

  if((which_dev = devintr()) == 0){
    printf("scause=0x%lx sepc=0x%lx stval=0x%lx\n", scause, r_sepc(), r_stval());
    panic("kerneltrap");
  }

  if(which_dev == 2 && myproc() != 0)
    yield();

  w_sepc(sepc);
  w_sstatus(sstatus);
}

void
clockintr()
{
  if(cpuid() == 0){
    acquire(&tickslock);
    ticks++;
    wakeup(&ticks);
    release(&tickslock);
  }
  w_stimecmp(r_time() + 1000000);
}

int
devintr()
{
  uint64 scause = r_scause();

  if(scause == 0x8000000000000009L){
    int irq = plic_claim();

    if(irq == UART0_IRQ){
      uartintr();
    } else if(irq == VIRTIO0_IRQ){
      virtio_disk_intr();
    } else if(irq){
      printf("unexpected interrupt irq=%d\n", irq);
    }

    if(irq)
      plic_complete(irq);

    return 1;
  } else if(scause == 0x8000000000000005L){
    clockintr();
    return 2;
  } else {
    return 0;
  }
}
