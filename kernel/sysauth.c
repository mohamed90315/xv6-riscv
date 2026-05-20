#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "fcntl.h"

#define PASSWD_FILE "/etc/passwd"
#define MAX_USERS 32
#define MAX_NAME  16
#define MAX_PASS  32
#define MAXBUF    1024

struct user_entry {
  char username[MAX_NAME];
  int uid;
  int gid;
  uint64 hash;
};

static int
streq(char *a, char *b)
{
  int i = 0;
  while(a[i] && b[i]){
    if(a[i] != b[i])
      return 0;
    i++;
  }
  return a[i] == 0 && b[i] == 0;
}

static int
strtoint(char *s)
{
  int n = 0;
  while(*s >= '0' && *s <= '9'){
    n = n * 10 + (*s - '0');
    s++;
  }
  return n;
}

static uint64
strtou64(char *s)
{
  uint64 n = 0;
  while(*s >= '0' && *s <= '9'){
    n = n * 10 + (*s - '0');
    s++;
  }
  return n;
}

static int
u64tostr(uint64 x, char *buf)
{
  char tmp[32];
  int i = 0, j;

  if(x == 0){
    buf[0] = '0';
    buf[1] = 0;
    return 1;
  }

  while(x > 0){
    tmp[i++] = '0' + (x % 10);
    x /= 10;
  }

  for(j = 0; j < i; j++)
    buf[j] = tmp[i - 1 - j];
  buf[i] = 0;
  return i;
}

static int
inttostr(int x, char *buf)
{
  return u64tostr((uint64)x, buf);
}

uint64
hash_djb2(char *str)
{
  uint64 hash = 5381;
  int c;

  while((c = *str++))
    hash = ((hash << 5) + hash) + c;

  return hash;
}

static int
read_passwd_file(struct user_entry *users, int *count)
{
  struct inode *ip;
  static char buf[MAXBUF];
  int n;

  begin_op();
  ip = namei(PASSWD_FILE);
  if(ip == 0){
    end_op();
    return -1;
  }

  ilock(ip);
  n = readi(ip, 0, (uint64)buf, 0, sizeof(buf) - 1);
  iunlockput(ip);
  end_op();

  if(n < 0)
    return -1;

  buf[n] = 0;
  *count = 0;

  char *line = buf;
  while(*line && *count < MAX_USERS){
    char *end = line;
    while(*end && *end != '\n')
      end++;

    if(end > line){
      char saved = *end;
      *end = 0;

      char *p1 = line;
      char *p2 = p1;
      while(*p2 && *p2 != ':') p2++;
      if(*p2){
        *p2++ = 0;
        safestrcpy(users[*count].username, p1, sizeof(users[*count].username));

        p1 = p2;
        while(*p2 && *p2 != ':') p2++;
        if(*p2){
          *p2++ = 0;
          users[*count].uid = strtoint(p1);

          p1 = p2;
          while(*p2 && *p2 != ':') p2++;
          if(*p2){
            *p2++ = 0;
            users[*count].gid = strtoint(p1);

            p1 = p2;
            users[*count].hash = strtou64(p1);
            (*count)++;
          }
        }
      }

      *end = saved;
    }

    if(*end == 0)
      break;
    line = end + 1;
  }

  return 0;
}

static int
write_passwd_file(struct user_entry *users, int count)
{
  struct inode *ip;
  char buf[MAXBUF];
  int len = 0;

  begin_op();
  ip = namei(PASSWD_FILE);
  if(ip == 0){
    end_op();
    return -1;
  }

  for(int i = 0; i < count; i++){
    char num[32];
    int l;

    l = strlen(users[i].username);
    if(len + l + 1 >= sizeof(buf))
      break;
    memmove(buf + len, users[i].username, l);
    len += l;
    buf[len++] = ':';

    l = inttostr(users[i].uid, num);
    if(len + l + 1 >= sizeof(buf))
      break;
    memmove(buf + len, num, l);
    len += l;
    buf[len++] = ':';

    l = inttostr(users[i].gid, num);
    if(len + l + 1 >= sizeof(buf))
      break;
    memmove(buf + len, num, l);
    len += l;
    buf[len++] = ':';

    l = u64tostr(users[i].hash, num);
    if(len + l + 1 >= sizeof(buf))
      break;
    memmove(buf + len, num, l);
    len += l;
    buf[len++] = '\n';
  }

  ilock(ip);
  itrunc(ip);
  if(writei(ip, 0, (uint64)buf, 0, len) != len){
    iunlockput(ip);
    end_op();
    return -1;
  }
  iupdate(ip);
  iunlockput(ip);
  end_op();

  return 0;
}

uint64
sys_login(void)
{
  char username[MAX_NAME], password[MAX_PASS];
  struct user_entry users[MAX_USERS];
  int count;

  if(argstr(0, username, sizeof(username)) < 0)
    return -1;
  if(argstr(1, password, sizeof(password)) < 0)
    return -1;

  if(read_passwd_file(users, &count) < 0)
    return -1;

  uint64 hash = hash_djb2(password);

  for(int i = 0; i < count; i++){
    if(streq(users[i].username, username)){
      if(users[i].hash == hash){
        struct proc *p = myproc();
        p->uid = users[i].uid;
        p->gid = users[i].gid;
        return 0;
      }
      return -1;
    }
  }

  return -1;
}

uint64
sys_useradd(void)
{
  char username[MAX_NAME], password[MAX_PASS];
  int uid, gid;
  struct user_entry users[MAX_USERS];
  int count;
  struct proc *p = myproc();

  if(p->uid != 0)
    return -1;

  if(argstr(0, username, sizeof(username)) < 0)
    return -1;
  argint(1, &uid);
  argint(2, &gid);
  if(argstr(3, password, sizeof(password)) < 0)
    return -1;

  if(read_passwd_file(users, &count) < 0)
    return -1;

  for(int i = 0; i < count; i++){
    if(streq(users[i].username, username))
      return -1;
  }

  if(count >= MAX_USERS)
    return -1;

  safestrcpy(users[count].username, username, sizeof(users[count].username));
  users[count].uid = uid;
  users[count].gid = gid;
  users[count].hash = hash_djb2(password);
  count++;

  return write_passwd_file(users, count);
}

uint64
sys_userdel(void)
{
  char username[MAX_NAME];
  struct user_entry users[MAX_USERS];
  int count, found = -1;
  struct proc *p = myproc();

  if(p->uid != 0)
    return -1;

  if(argstr(0, username, sizeof(username)) < 0)
    return -1;

  if(read_passwd_file(users, &count) < 0)
    return -1;

  for(int i = 0; i < count; i++){
    if(streq(users[i].username, username)){
      found = i;
      break;
    }
  }

  if(found < 0)
    return -1;

  for(int i = found; i < count - 1; i++)
    users[i] = users[i + 1];
  count--;

  return write_passwd_file(users, count);
}

uint64
sys_passwd(void)
{
  char username[MAX_NAME], newpassword[MAX_PASS];
  struct user_entry users[MAX_USERS];
  int count;
  struct proc *p = myproc();

  if(argstr(0, username, sizeof(username)) < 0)
    return -1;
  if(argstr(1, newpassword, sizeof(newpassword)) < 0)
    return -1;

  if(read_passwd_file(users, &count) < 0)
    return -1;

  for(int i = 0; i < count; i++){
    if(streq(users[i].username, username)){
      if(p->uid != 0 && p->uid != users[i].uid)
        return -1;
      users[i].hash = hash_djb2(newpassword);
      return write_passwd_file(users, count);
    }
  }

  return -1;
}

uint64
sys_whoami(void)
{
  struct proc *p = myproc();
  struct user_entry users[MAX_USERS];
  int count;

  if(read_passwd_file(users, &count) == 0){
    for(int i = 0; i < count; i++){
      if(users[i].uid == p->uid){
        printf("uid=%d(%s) gid=%d\n", p->uid, users[i].username, p->gid);
        return 0;
      }
    }
  }

  printf("uid=%d gid=%d\n", p->uid, p->gid);
  return 0;
}



