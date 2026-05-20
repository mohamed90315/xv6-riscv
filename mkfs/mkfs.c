#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>

#define stat xv6_stat  // avoid clash with host struct stat
#include "kernel/types.h"
#include "kernel/fs.h"
#include "kernel/stat.h"
#include "kernel/param.h"

#ifndef static_assert
#define static_assert(a, b) do { switch (0) case 0: case (a): ; } while (0)
#endif

#define NINODES 200

int nbitmap = FSSIZE/BPB + 1;
int ninodeblocks = NINODES / IPB + 1;
int nlog = LOGBLOCKS+1;
int nmeta;
int nblocks;

int fsfd;
struct superblock sb;
char zeroes[BSIZE];
uint freeinode = 1;
uint freeblock;

void balloc(int);
void wsect(uint, void*);
void winode(uint, struct dinode*);
void rinode(uint inum, struct dinode *ip);
void rsect(uint sec, void *buf);
uint ialloc(ushort type);
void iappend(uint inum, void *p, int n);
void die(const char *);

// ✅ djb2 hash - must match kernel/sysauth.c
unsigned long long
hash_djb2(char *str)
{
  unsigned long long hash = 5381;
  int c;
  while((c = *str++))
    hash = ((hash << 5) + hash) + c;
  return hash;
}

ushort
xshort(ushort x)
{
  ushort y;
  uchar *a = (uchar*)&y;
  a[0] = x;
  a[1] = x >> 8;
  return y;
}

uint
xint(uint x)
{
  uint y;
  uchar *a = (uchar*)&y;
  a[0] = x;
  a[1] = x >> 8;
  a[2] = x >> 16;
  a[3] = x >> 24;
  return y;
}

int
main(int argc, char *argv[])
{
  int i, cc, fd;
  uint rootino, inum, off;
  struct dirent de;
  char buf[BSIZE];
  struct dinode din;

  static_assert(sizeof(int) == 4, "Integers must be 4 bytes!");

  if(argc < 2){
    fprintf(stderr, "Usage: mkfs fs.img files...\n");
    exit(1);
  }

  assert((BSIZE % sizeof(struct dinode)) == 0);
  assert((BSIZE % sizeof(struct dirent)) == 0);

  fsfd = open(argv[1], O_RDWR|O_CREAT|O_TRUNC, 0666);
  if(fsfd < 0)
    die(argv[1]);

  nmeta = 2 + nlog + ninodeblocks + nbitmap;
  nblocks = FSSIZE - nmeta;

  sb.magic = FSMAGIC;
  sb.size = xint(FSSIZE);
  sb.nblocks = xint(nblocks);
  sb.ninodes = xint(NINODES);
  sb.nlog = xint(nlog);
  sb.logstart = xint(2);
  sb.inodestart = xint(2+nlog);
  sb.bmapstart = xint(2+nlog+ninodeblocks);

  printf("nmeta %d (boot, super, log blocks %u, inode blocks %u, bitmap blocks %u) blocks %d total %d\n",
         nmeta, nlog, ninodeblocks, nbitmap, nblocks, FSSIZE);

  freeblock = nmeta;

  for(i = 0; i < FSSIZE; i++)
    wsect(i, zeroes);

  memset(buf, 0, sizeof(buf));
  memmove(buf, &sb, sizeof(sb));
  wsect(1, buf);

  rootino = ialloc(T_DIR);
  assert(rootino == ROOTINO);

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, ".");
  iappend(rootino, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(rootino, &de, sizeof(de));

  // ============================================================
  // CREATE /etc DIRECTORY
  // ============================================================

  printf("Creating /etc directory...\n");

  uint etc_inum = ialloc(T_DIR);

  bzero(&de, sizeof(de));
  de.inum = xshort(etc_inum);
  strcpy(de.name, ".");
  iappend(etc_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(etc_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(etc_inum);
  strcpy(de.name, "etc");
  iappend(rootino, &de, sizeof(de));

  // ============================================================
  // CREATE /etc/passwd FILE
  // ============================================================

  printf("Creating /etc/passwd...\n");

  // ✅ Compute hashes at build time - guaranteed correct
  unsigned long long h_admin   = hash_djb2("admin123");
  unsigned long long h_patient = hash_djb2("patient123");
  unsigned long long h_doctor  = hash_djb2("doctor123");

  printf("Hash admin123   = %llu\n", h_admin);
  printf("Hash patient123 = %llu\n", h_patient);
  printf("Hash doctor123  = %llu\n", h_doctor);

  char passwd_content[512];
  snprintf(passwd_content, sizeof(passwd_content),
    "admin:0:0:%llu\n"
    "patient:1:1:%llu\n"
    "doctor:2:2:%llu\n",
    h_admin, h_patient, h_doctor);

  printf("passwd content:\n%s\n", passwd_content);

  uint passwd_inum = ialloc(T_FILE);
  iappend(passwd_inum, passwd_content, strlen(passwd_content));

  // Set passwd permissions
  rinode(passwd_inum, &din);
  din.uid  = xshort(0);
  din.gid  = xshort(0);
  din.mode = xshort(0644);
  winode(passwd_inum, &din);

  bzero(&de, sizeof(de));
  de.inum = xshort(passwd_inum);
  strcpy(de.name, "passwd");
  iappend(etc_inum, &de, sizeof(de));

  // ============================================================
  // CREATE /patient DIRECTORY
  // ============================================================

  printf("Creating /patient directory...\n");

  uint patient_dir_inum = ialloc(T_DIR);

  bzero(&de, sizeof(de));
  de.inum = xshort(patient_dir_inum);
  strcpy(de.name, ".");
  iappend(patient_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(patient_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(patient_dir_inum);
  strcpy(de.name, "patient");
  iappend(rootino, &de, sizeof(de));

  // Create /patient/records
  printf("Creating /patient/records...\n");

  uint records_inum = ialloc(T_FILE);

  char records_content[] = "Patient Medical Records\nConfidential Information\n";
  iappend(records_inum, records_content, strlen(records_content));

  bzero(&de, sizeof(de));
  de.inum = xshort(records_inum);
  strcpy(de.name, "records");
  iappend(patient_dir_inum, &de, sizeof(de));

  rinode(records_inum, &din);
  din.uid  = xshort(1);
  din.gid  = xshort(1);
  din.mode = xshort(0444);
  winode(records_inum, &din);

  // ============================================================
  // CREATE /dosage DIRECTORY
  // ============================================================

  printf("Creating /dosage directory...\n");

  uint dosage_dir_inum = ialloc(T_DIR);

  bzero(&de, sizeof(de));
  de.inum = xshort(dosage_dir_inum);
  strcpy(de.name, ".");
  iappend(dosage_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(dosage_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(dosage_dir_inum);
  strcpy(de.name, "dosage");
  iappend(rootino, &de, sizeof(de));

  // Create /dosage/insulin.log
  printf("Creating /dosage/insulin.log...\n");

  uint insulin_inum = ialloc(T_FILE);

  char insulin_content[] = "Insulin Dosage Log\nTimestamp,Dosage(units),Patient_ID\n";
  iappend(insulin_inum, insulin_content, strlen(insulin_content));

  bzero(&de, sizeof(de));
  de.inum = xshort(insulin_inum);
  strcpy(de.name, "insulin.log");
  iappend(dosage_dir_inum, &de, sizeof(de));

  rinode(insulin_inum, &din);
  din.uid  = xshort(2);
  din.gid  = xshort(1);
  din.mode = xshort(0644);
  winode(insulin_inum, &din);

  // ============================================================
  // CREATE /device DIRECTORY
  // ============================================================

  printf("Creating /device directory...\n");

  uint device_dir_inum = ialloc(T_DIR);

  bzero(&de, sizeof(de));
  de.inum = xshort(device_dir_inum);
  strcpy(de.name, ".");
  iappend(device_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(device_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(device_dir_inum);
  strcpy(de.name, "device");
  iappend(rootino, &de, sizeof(de));

  rinode(device_dir_inum, &din);
  din.uid  = xshort(0);
  din.gid  = xshort(0);
  din.mode = xshort(0700);
  winode(device_dir_inum, &din);

  // Create /device/config
  printf("Creating /device/config...\n");

  uint config_inum = ialloc(T_FILE);

  char config_content[] = "Device Configuration File\nAdmin Access Only\nCritical Settings\n";
  iappend(config_inum, config_content, strlen(config_content));

  bzero(&de, sizeof(de));
  de.inum = xshort(config_inum);
  strcpy(de.name, "config");
  iappend(device_dir_inum, &de, sizeof(de));

  rinode(config_inum, &din);
  din.uid  = xshort(0);
  din.gid  = xshort(0);
  din.mode = xshort(0600);
  winode(config_inum, &din);

  // ============================================================
  // CREATE /audit DIRECTORY
  // ============================================================

  printf("Creating /audit directory...\n");

  uint audit_dir_inum = ialloc(T_DIR);

  bzero(&de, sizeof(de));
  de.inum = xshort(audit_dir_inum);
  strcpy(de.name, ".");
  iappend(audit_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(rootino);
  strcpy(de.name, "..");
  iappend(audit_dir_inum, &de, sizeof(de));

  bzero(&de, sizeof(de));
  de.inum = xshort(audit_dir_inum);
  strcpy(de.name, "audit");
  iappend(rootino, &de, sizeof(de));

  rinode(audit_dir_inum, &din);
  din.uid  = xshort(0);
  din.gid  = xshort(0);
  din.mode = xshort(0700);
  winode(audit_dir_inum, &din);

  // Create /audit/syscall.log
  printf("Creating /audit/syscall.log...\n");

  uint syscall_log_inum = ialloc(T_FILE);

  char syscall_log_content[] = "System Call Audit Log\nAdmin Access Only\n";
  iappend(syscall_log_inum, syscall_log_content, strlen(syscall_log_content));

  bzero(&de, sizeof(de));
  de.inum = xshort(syscall_log_inum);
  strcpy(de.name, "syscall.log");
  iappend(audit_dir_inum, &de, sizeof(de));

  rinode(syscall_log_inum, &din);
  din.uid  = xshort(0);
  din.gid  = xshort(0);
  din.mode = xshort(0600);
  winode(syscall_log_inum, &din);

  printf("Security filesystem structure created successfully\n");

  // ============================================================
  // ADD USER PROGRAMS
  // ============================================================

  for(i = 2; i < argc; i++){
    char *shortname;
    if(strncmp(argv[i], "user/", 5) == 0)
      shortname = argv[i] + 5;
    else
      shortname = argv[i];

    assert(index(shortname, '/') == 0);

    if((fd = open(argv[i], 0)) < 0)
      die(argv[i]);

    if(shortname[0] == '_')
      shortname += 1;

    assert(strlen(shortname) <= DIRSIZ);

    inum = ialloc(T_FILE);

    bzero(&de, sizeof(de));
    de.inum = xshort(inum);
    strncpy(de.name, shortname, DIRSIZ);
    iappend(rootino, &de, sizeof(de));

    while((cc = read(fd, buf, sizeof(buf))) > 0)
      iappend(inum, buf, cc);

    close(fd);
  }

  // fix size of root inode dir
  rinode(rootino, &din);
  off = xint(din.size);
  off = ((off/BSIZE) + 1) * BSIZE;
  din.size = xint(off);
  winode(rootino, &din);

  balloc(freeblock);

  exit(0);
}

void
wsect(uint sec, void *buf)
{
  if(lseek(fsfd, sec * BSIZE, 0) != sec * BSIZE)
    die("lseek");
  if(write(fsfd, buf, BSIZE) != BSIZE)
    die("write");
}

void
winode(uint inum, struct dinode *ip)
{
  char buf[BSIZE];
  uint bn;
  struct dinode *dip;

  bn = IBLOCK(inum, sb);
  rsect(bn, buf);
  dip = ((struct dinode*)buf) + (inum % IPB);
  *dip = *ip;
  wsect(bn, buf);
}

void
rinode(uint inum, struct dinode *ip)
{
  char buf[BSIZE];
  uint bn;
  struct dinode *dip;

  bn = IBLOCK(inum, sb);
  rsect(bn, buf);
  dip = ((struct dinode*)buf) + (inum % IPB);
  *ip = *dip;
}

void
rsect(uint sec, void *buf)
{
  if(lseek(fsfd, sec * BSIZE, 0) != sec * BSIZE)
    die("lseek");
  if(read(fsfd, buf, BSIZE) != BSIZE)
    die("read");
}

uint
ialloc(ushort type)
{
  uint inum = freeinode++;
  struct dinode din;

  bzero(&din, sizeof(din));
  din.type  = xshort(type);
  din.nlink = xshort(1);
  din.size  = xint(0);
  din.uid   = xshort(0);
  din.gid   = xshort(0);
  din.mode  = xshort(0755);
  winode(inum, &din);
  return inum;
}

void
balloc(int used)
{
  uchar buf[BSIZE];
  int i;

  printf("balloc: first %d blocks have been allocated\n", used);
  assert(used < BPB);
  bzero(buf, BSIZE);
  for(i = 0; i < used; i++){
    buf[i/8] = buf[i/8] | (0x1 << (i%8));
  }
  printf("balloc: write bitmap block at sector %d\n", sb.bmapstart);
  wsect(sb.bmapstart, buf);
}

#define min(a, b) ((a) < (b) ? (a) : (b))

void
iappend(uint inum, void *xp, int n)
{
  char *p = (char*)xp;
  uint fbn, off, n1;
  struct dinode din;
  char buf[BSIZE];
  uint indirect[NINDIRECT];
  uint x;

  rinode(inum, &din);
  off = xint(din.size);
  while(n > 0){
    fbn = off / BSIZE;
    assert(fbn < MAXFILE);
    if(fbn < NDIRECT){
      if(xint(din.addrs[fbn]) == 0){
        din.addrs[fbn] = xint(freeblock++);
      }
      x = xint(din.addrs[fbn]);
    } else {
      if(xint(din.addrs[NDIRECT]) == 0){
        din.addrs[NDIRECT] = xint(freeblock++);
      }
      rsect(xint(din.addrs[NDIRECT]), (char*)indirect);
      if(indirect[fbn - NDIRECT] == 0){
        indirect[fbn - NDIRECT] = xint(freeblock++);
        wsect(xint(din.addrs[NDIRECT]), (char*)indirect);
      }
      x = xint(indirect[fbn-NDIRECT]);
    }
    n1 = min(n, (fbn + 1) * BSIZE - off);
    rsect(x, buf);
    bcopy(p, buf + off - (fbn * BSIZE), n1);
    wsect(x, buf);
    n -= n1;
    off += n1;
    p += n1;
  }
  din.size = xint(off);
  winode(inum, &din);
}

void
die(const char *s)
{
  perror(s);
  exit(1);
}
