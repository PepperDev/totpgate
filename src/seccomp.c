#include "seccomp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#if defined(__x86_64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_AARCH64
#else
#error "unsupported architecture for seccomp filter"
#endif

#define ALLOW(syscall) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

int install_seccomp(int foreground)
{
  struct sock_filter filter[] = {
    /* validate architecture */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

    /* load syscall number */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),

    /* allowed syscalls */
    ALLOW(SYS_read),
    ALLOW(SYS_write),
    ALLOW(SYS_writev),
    ALLOW(SYS_close),
    ALLOW(SYS_mmap),
    ALLOW(SYS_mprotect),
    ALLOW(SYS_munmap),
    ALLOW(SYS_brk),
    ALLOW(SYS_rt_sigaction),
    ALLOW(SYS_rt_sigprocmask),
    ALLOW(SYS_getpid),
    ALLOW(SYS_gettimeofday),
    ALLOW(SYS_sendto),
    ALLOW(SYS_recvfrom),
    ALLOW(SYS_exit),
    ALLOW(SYS_arch_prctl),
    ALLOW(SYS_futex),
    ALLOW(SYS_clock_gettime),
    ALLOW(SYS_poll),
    ALLOW(SYS_epoll_wait),
    ALLOW(SYS_epoll_pwait),
    ALLOW(SYS_epoll_ctl),
    ALLOW(SYS_exit_group),
    ALLOW(SYS_getrandom),

    /* deny everything else */
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };

  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) != 0) {
    if (foreground)
      fprintf(stderr, "warning: seccomp filter not available: %s\n", strerror(errno));
    else
      syslog(LOG_WARNING, "seccomp filter not available: %s", strerror(errno));
    return -1;
  }

  if (foreground)
    fprintf(stderr, "seccomp filter installed\n");
  else
    syslog(LOG_INFO, "seccomp filter installed");
  return 0;
}
