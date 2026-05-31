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
#elif defined(__i386__) || defined(__i686__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_I386
#elif defined(__aarch64__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_AARCH64
#elif defined(__arm__)
#define AUDIT_ARCH_NATIVE AUDIT_ARCH_ARM
#else
#error "unsupported architecture for seccomp filter"
#endif

#define ALLOW(syscall) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

static void msg_fail(int foreground)
{
  if (foreground)
    fprintf(stderr, "warning: seccomp filter not available: %s\n", strerror(errno));
  else
    syslog(LOG_WARNING, "seccomp filter not available: %s", strerror(errno));
}

static void msg_ok(int foreground)
{
  if (foreground)
    fprintf(stderr, "seccomp filter installed\n");
  else
    syslog(LOG_INFO, "seccomp filter installed");
}

static int apply_filter(void)
{
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_NATIVE, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),

    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 0),

    ALLOW(SYS_read),
    ALLOW(SYS_write),
    ALLOW(SYS_writev),
    ALLOW(SYS_close),
#ifdef SYS_mmap
    ALLOW(SYS_mmap),
#endif
#ifdef SYS_mmap2
    ALLOW(SYS_mmap2),
#endif
    ALLOW(SYS_mprotect),
    ALLOW(SYS_munmap),
    ALLOW(SYS_brk),
    ALLOW(SYS_rt_sigaction),
    ALLOW(SYS_rt_sigprocmask),
    ALLOW(SYS_getpid),
#ifdef SYS_gettimeofday
    ALLOW(SYS_gettimeofday),
#endif
    ALLOW(SYS_sendto),
    ALLOW(SYS_recvfrom),
    ALLOW(SYS_exit),
#ifdef SYS_arch_prctl
    ALLOW(SYS_arch_prctl),
#endif
    ALLOW(SYS_futex),
#ifdef SYS_clock_gettime
    ALLOW(SYS_clock_gettime),
#endif
#ifdef SYS_clock_gettime64
    ALLOW(SYS_clock_gettime64),
#endif
#ifdef SYS_poll
    ALLOW(SYS_poll),
#endif
#ifdef SYS_ppoll
    ALLOW(SYS_ppoll),
#endif
#ifdef SYS_epoll_wait
    ALLOW(SYS_epoll_wait),
#endif
    ALLOW(SYS_epoll_pwait),
    ALLOW(SYS_epoll_ctl),
    ALLOW(SYS_exit_group),
    ALLOW(SYS_getrandom),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL),
  };

  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int install_seccomp(int foreground)
{
  if (apply_filter() != 0) {
    msg_fail(foreground);
    return -1;
  }
  msg_ok(foreground);
  return 0;
}
