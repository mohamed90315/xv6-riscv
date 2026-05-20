#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

struct audit_entry {
  int pid;
  int uid;
  int trapno;
  int tick;
  char desc[32];
};

#define MAX_ENTRIES 50
static struct audit_entry entries[MAX_ENTRIES];

static int passed = 0;
static int failed = 0;

void
test_result(char *name, int ok)
{
  if(ok){
    printf("[PASS] %s\n", name);
    passed++;
  } else {
    printf("[FAIL] %s\n", name);
    failed++;
  }
}

// ─────────────────────────────────────────
// PHASE 1 TESTS
// ─────────────────────────────────────────

void
test_wrong_password(void)
{
  int r = login("admin", "wrongpassword");
  test_result("Auth: wrong password rejected", r < 0);
}

void
test_correct_password(void)
{
  int r = login("admin", "admin123");
  test_result("Auth: correct password accepted", r == 0);
}

void
test_whoami_uid(void)
{
  login("patient", "patient123");
  int r = whoami();
  test_result("Auth: whoami returns uid correctly", r == 0);
}

void
test_useradd_admin(void)
{
  login("admin", "admin123");
  int r = useradd("testuser", 10, 10, "testpass123");
  test_result("Auth: admin can useradd", r == 0);
}

void
test_userdel_admin(void)
{
  login("admin", "admin123");
  int r = userdel("testuser");
  test_result("Auth: admin can userdel", r == 0);
}

void
test_useradd_nonadmin(void)
{
  login("patient", "patient123");
  int r = useradd("hacker", 99, 99, "hack123");
  test_result("Auth: non-admin cannot useradd", r < 0);
}

// ─────────────────────────────────────────
// PHASE 2 TESTS
// ─────────────────────────────────────────

void
test_patient_blocked_config(void)
{
  login("patient", "patient123");
  int fd = open("/device/config", O_RDONLY);
  int blocked = (fd < 0);
  if(fd >= 0) close(fd);
  test_result("Perm: patient blocked from /device/config", blocked);
}

void
test_patient_read_records(void)
{
  login("patient", "patient123");
  int fd = open("/patient/records", O_RDONLY);
  int ok = (fd >= 0);
  if(fd >= 0) close(fd);
  test_result("Perm: patient can read /patient/records", ok);
}

void
test_doctor_write_insulin(void)
{
  login("doctor", "doctor123");
  int fd = open("/dosage/insulin.log", O_WRONLY);
  int ok = (fd >= 0);
  if(fd >= 0){
    write(fd, "test\n", 5);
    close(fd);
  }
  test_result("Perm: doctor can write /dosage/insulin.log", ok);
}

void
test_patient_no_write_insulin(void)
{
  login("patient", "patient123");
  int fd = open("/dosage/insulin.log", O_WRONLY);
  int blocked = (fd < 0);
  if(fd >= 0) close(fd);
  test_result("Perm: patient cannot write /dosage/insulin.log", blocked);
}

void
test_admin_access_all(void)
{
  login("admin", "admin123");
  int fd1 = open("/device/config", O_RDONLY);
  int fd2 = open("/audit/syscall.log", O_RDONLY);
  int fd3 = open("/dosage/insulin.log", O_RDWR);
  int ok = (fd1 >= 0 && fd2 >= 0 && fd3 >= 0);
  if(fd1 >= 0) close(fd1);
  if(fd2 >= 0) close(fd2);
  if(fd3 >= 0) close(fd3);
  test_result("Perm: admin can access all files", ok);
}

void
test_chmod_blocked_nonowner(void)
{
  login("patient", "patient123");
  int r = chmod("/device/config", 0777);
  test_result("Perm: chmod blocked for non-owner", r < 0);
}

void
test_chown_blocked_nonadmin(void)
{
  login("doctor", "doctor123");
  int r = chown("/dosage/insulin.log", 0);
  test_result("Perm: chown blocked for non-admin", r < 0);
}

// ─────────────────────────────────────────
// PHASE 3 TESTS
// ─────────────────────────────────────────

void
test_audit_populated(void)
{
  login("admin", "admin123");
  int n = audit_read(entries, MAX_ENTRIES);
  test_result("Audit: log populated after access attempts", n > 0);
}

void
test_audit_nonadmin_eperm(void)
{
  login("patient", "patient123");
  int n = audit_read(entries, MAX_ENTRIES);
  test_result("Audit: non-admin audit_read returns EPERM", n < 0);
}

void
test_audit_admin_read(void)
{
  login("admin", "admin123");
  int n = audit_read(entries, MAX_ENTRIES);
  test_result("Audit: admin can read audit log", n >= 0);
}

// ─────────────────────────────────────────
// INTEGRATION TEST
// ─────────────────────────────────────────

void
test_integration_attack_flow(void)
{
  printf("\n--- Integration: Attack Detection Flow ---\n");

  // Step 1: Unauthorized access
  printf("  Step 1: patient attempts unauthorized access...\n");
  login("patient", "patient123");
  int fd = open("/device/config", O_RDONLY);
  int blocked = (fd < 0);
  if(fd >= 0) close(fd);
  if(blocked)
    printf("  [OK] Access denied as expected\n");
  else
    printf("  [FAIL] Access was granted!\n");

  // Step 2: Doctor successful write
  printf("  Step 2: doctor writes to dosage log...\n");
  login("doctor", "doctor123");
  fd = open("/dosage/insulin.log", O_WRONLY);
  int doc_ok = (fd >= 0);
  if(fd >= 0){
    write(fd, "20units\n", 8);
    close(fd);
    printf("  [OK] Doctor write succeeded\n");
  } else {
    printf("  [FAIL] Doctor write failed\n");
  }

  // Step 3: Admin reads audit log
  printf("  Step 3: admin checks audit log for evidence...\n");
  login("admin", "admin123");
  int n = audit_read(entries, MAX_ENTRIES);

  printf("\n  Evidence from audit log (last 10 entries):\n");
  int start = n > 10 ? n - 10 : 0;
  for(int i = start; i < n; i++){
    printf("  [LOG] PID=%d UID=%d TRAP=%d TICK=%d DESC=%s\n",
           entries[i].pid,
           entries[i].uid,
           entries[i].trapno,
           entries[i].tick,
           entries[i].desc);
  }

  test_result("Integration: attack flow detected in audit log",
              blocked && doc_ok && n > 0);
}

// ─────────────────────────────────────────
// MAIN
// ─────────────────────────────────────────

int
main(void)
{
  printf("+----------------------------------------------+\n");
  printf("|   xv6 Security Compliance Test Suite        |\n");
  printf("|   Medical Device Security Simulation        |\n");
  printf("+----------------------------------------------+\n\n");

  printf("=== PHASE 1: Authentication Tests ===\n");
  test_wrong_password();
  test_correct_password();
  test_whoami_uid();
  test_useradd_admin();
  test_userdel_admin();
  test_useradd_nonadmin();

  printf("\n=== PHASE 2: Permission Tests ===\n");
  test_patient_blocked_config();
  test_patient_read_records();
  test_doctor_write_insulin();
  test_patient_no_write_insulin();
  test_admin_access_all();
  test_chmod_blocked_nonowner();
  test_chown_blocked_nonadmin();

  printf("\n=== PHASE 3: Audit Tests ===\n");
  test_audit_populated();
  test_audit_nonadmin_eperm();
  test_audit_admin_read();

  printf("\n=== INTEGRATION TEST ===\n");
  test_integration_attack_flow();

  printf("\n+----------------------------------------------+\n");
  printf("|           COMPLIANCE SUMMARY                 |\n");
  printf("+----------------------------------------------+\n");
  printf("|  Total Tests : %d\n", passed + failed);
  printf("|  Passed      : %d\n", passed);
  printf("|  Failed      : %d\n", failed);
  printf("+----------------------------------------------+\n");

  if(failed == 0){
    printf("|  Status: COMPLIANT - ALL TESTS PASSED        |\n");
    printf("+----------------------------------------------+\n");
    exit(0);
  } else {
    printf("|  Status: NON-COMPLIANT - SOME TESTS FAILED   |\n");
    printf("+----------------------------------------------+\n");
    exit(1);
  }
}
