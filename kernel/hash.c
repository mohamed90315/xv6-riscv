#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"

// djb2 hash function
unsigned long
hash_djb2(char *str)
{
  unsigned long hash = 5381;
  int c;
  
  while ((c = *str++))
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  
  return hash;
}
