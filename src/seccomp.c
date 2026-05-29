#include "seccomp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

/* x86_64 syscall numbers */
#define SYS_read 0
#define SYS_write 1
#define SYS_writev 20
#define SYS_close 3
#define SYS_mmap 9
#define SYS_mprotect 10
#define SYS_munmap 11
#define SYS_brk 12
#define SYS_rt_sigaction 13
#define SYS_rt_sigprocmask 14
#define SYS_getpid 39
#define SYS_sendto 44
#define SYS_recvfrom 45
#define SYS_exit 60
#define SYS_arch_prctl 158
#define SYS_futex 202
#define SYS_clock_gettime 228
#define SYS_exit_group 231
#define SYS_epoll_wait 232
#define SYS_epoll_ctl 233
#define SYS_getrandom 318
#define SYS_epoll_pwait 281
#define SYS_gettimeofday 96

#define ALLOW(syscall) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

int install_seccomp(int foreground)
{
  struct sock_filter filter[] = {
    /* validate architecture */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, 4),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
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
