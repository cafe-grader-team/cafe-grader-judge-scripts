/*
 *	A Simple Sandbox for Moe
 *
 *	(c) 2001--2010 Martin Mares <mj@ucw.cz>
 */

#define _LARGEFILE64_SOURCE
#define _GNU_SOURCE

/* Generated automatically by ./configure, please don't touch manually. */
#define CONFIG_BOX_KERNEL_AMD64 1
#define CONFIG_BOX_USER_AMD64 1
#define CONFIG_DIR "cf"
#define CONFIG_DIRECT_IO 1
#define CONFIG_ISOLATE_BOX_DIR "/tmp/box"
#define CONFIG_ISOLATE_CGROUP_ROOT "/sys/fs/cgroup"
#define CONFIG_ISOLATE_FIRST_GID 60000
#define CONFIG_ISOLATE_FIRST_UID 60000
#define CONFIG_ISOLATE_NUM_BOXES 100
#define CONFIG_LARGE_FILES 1
#define CONFIG_LFS 1
#define CONFIG_LINUX 1
#define CONFIG_LOCAL 1
#define CONFIG_UCW_PARTMAP_IS_MMAP 1
#define CONFIG_UCW_PERL 1
#define CONFIG_UCW_POOL_IS_MMAP 1
#define CONFIG_UCW_RADIX_SORTER_BITS 10
#define CONFIG_UCW_SHELL_UTILS 1
#define CPU_64BIT_POINTERS 1
#define CPU_ALLOW_UNALIGNED 1
#define CPU_AMD64 1
#define CPU_ARCH "default"
#define CPU_LITTLE_ENDIAN 1
#define CPU_PAGE_SIZE 4096
#define CPU_STRUCT_ALIGN 8
#define CWARNS_OFF " -Wno-pointer-sign"
#define HAVE_ASCII_DOC "none"
#define INSTALL_BIN_DIR "bin"
#define INSTALL_CONFIG_DIR "cf"
#define INSTALL_DOC_DIR "share/doc"
#define INSTALL_INCLUDE_DIR "include"
#define INSTALL_LIB_DIR "lib"
#define INSTALL_LOG_DIR "log"
#define INSTALL_MAN_DIR "share/man"
#define INSTALL_PERL_DIR "lib/perl5"
#define INSTALL_PKGCONFIG_DIR "lib/pkgconfig"
#define INSTALL_PREFIX 
#define INSTALL_RUN_DIR "run"
#define INSTALL_SBIN_DIR "sbin"
#define INSTALL_SHARE_DIR "share"
#define INSTALL_STATE_DIR "lib"
#define INSTALL_USR_PREFIX 
#define INSTALL_VAR_PREFIX 
#define SHERLOCK_VERSION "3.99.2"
#define SHERLOCK_VERSION_CODE 3099002
#define SONAME_PREFIX "lib/"
#define UCW_VERSION "3.99.2"
#define UCW_VERSION_CODE 3099002

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/sysinfo.h>
#include <sys/resource.h>
#include <sys/utsname.h>
//#include <linux/ptrace.h>

#if defined(CONFIG_BOX_KERNEL_AMD64) && !defined(CONFIG_BOX_USER_AMD64)
#include <asm/unistd_32.h>
#define NATIVE_NR_execve 59		/* 64-bit execve */
#else
#include <asm/unistd.h>
#define NATIVE_NR_execve __NR_execve
#endif

#define NONRET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define ARRAY_SIZE(a) (int)(sizeof(a)/sizeof(a[0]))

static int filter_syscalls;		/* 0=off, 1=liberal, 2=totalitarian */
static int timeout;			/* milliseconds */
static int wall_timeout;
static int extra_timeout;
static int pass_environ;
static int file_access;
static int verbose;
static int memory_limit;
static int stack_limit;
static char *redir_stdin, *redir_stdout, *redir_stderr;
static char *set_cwd;

static pid_t box_pid;
static int is_ptraced;
static volatile int timer_tick;
static struct timeval start_time;
static int ticks_per_sec;
static int exec_seen;
static int partial_line;

static int mem_peak_kb;
static int total_ms, wall_ms, sys_ms;

static void die(char *msg, ...) NONRET;
static void sample_mem_peak(void);

/*** Meta-files ***/

static FILE *metafile;

static void
meta_open(const char *name)
{
  if (!strcmp(name, "-"))
    {
      metafile = stdout;
      return;
    }
  metafile = fopen(name, "w");
  if (!metafile)
    die("Failed to open metafile '%s'",name);
}

static void
meta_close(void)
{
  if (metafile && metafile != stdout)
    fclose(metafile);
}

static void __attribute__((format(printf,1,2)))
meta_printf(const char *fmt, ...)
{
  if (!metafile)
    return;

  va_list args;
  va_start(args, fmt);
  vfprintf(metafile, fmt, args);
  va_end(args);
}


static void print_running_stat(double wall_time,
			double user_time,
			double system_time,
			int mem_usage)
{
  //total is user
  //wall is wall
  //
  fprintf(stderr,"%.4lfr%.4lfu%.4lfs%dkbytes\n", 
	  wall_time, user_time, system_time, mem_usage);
}

static void
final_stats(struct rusage *rus)
{
  struct timeval total, now, wall;
  timeradd(&rus->ru_utime, &rus->ru_stime, &total);
  total_ms = total.tv_sec*1000 + total.tv_usec/1000;
  gettimeofday(&now, NULL);
  timersub(&now, &start_time, &wall);
  wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;
  sys_ms = rus->ru_stime.tv_sec * 1000 + rus->ru_stime.tv_usec / 1000;

  meta_printf("time:%d.%03d\n", total_ms/1000, total_ms%1000);
  meta_printf("time-wall:%d.%03d\n", wall_ms/1000, wall_ms%1000);
  meta_printf("mem:%llu\n", (unsigned long long) mem_peak_kb * 1024);
}

/*** Messages and exits ***/

static void NONRET
box_exit(int rc)
{
  if (box_pid > 0)
    {
      sample_mem_peak();
      if (is_ptraced)
	ptrace(PTRACE_KILL, box_pid);
      kill(-box_pid, SIGKILL);
      kill(box_pid, SIGKILL);
      meta_printf("killed:1\n");

      struct rusage rus;
      int p, stat;
      do
	p = wait4(box_pid, &stat, 0, &rus);
      while (p < 0 && errno == EINTR);
      if (p < 0)
	fprintf(stderr, "UGH: Lost track of the process (%m)\n");
      else {
	final_stats(&rus);
      }
    }
  print_running_stat(
        (double)wall_ms/1000,
        (double)total_ms/1000,
        (double)sys_ms/1000,
        mem_peak_kb);
  meta_close();
  exit(rc);
}

static void
flush_line(void)
{
  if (partial_line)
    fputc('\n', stderr);
  partial_line = 0;
}

/* Report an error of the sandbox itself */
static void NONRET __attribute__((format(printf,1,2)))
die(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  flush_line();
  char buf[1024];
  vsnprintf(buf, sizeof(buf), msg, args);
  meta_printf("status:XX\nmessage:%s\n", buf);
  fputs(buf, stderr);
  fputc('\n', stderr);
  box_exit(2);
}

/* Report an error of the program inside the sandbox */
static void NONRET __attribute__((format(printf,1,2)))
err(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  flush_line();
  if (msg[0] && msg[1] && msg[2] == ':' && msg[3] == ' ')
    {
      meta_printf("status:%c%c\n", msg[0], msg[1]);
      msg += 4;
    }
  char buf[1024];
  vsnprintf(buf, sizeof(buf), msg, args);
  meta_printf("message:%s\n", buf);
  fputs(buf, stderr);
  fputc('\n', stderr);
  box_exit(1);
}

/* Write a message, but only if in verbose mode */
static void __attribute__((format(printf,1,2)))
msg(char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  if (verbose)
    {
      int len = strlen(msg);
      if (len > 0)
        partial_line = (msg[len-1] != '\n');
      vfprintf(stderr, msg, args);
      fflush(stderr);
    }
  va_end(args);
}

static void *
xmalloc(size_t size)
{
  void *p = malloc(size);
  if (!p)
    die("Out of memory");
  return p;
}

/*** Syscall rules ***/

static const char * const syscall_names[] = {

/* Syscall table automatically generated by mk-syscall-table */

/* 0 */ [ __NR_read ] = "read",
/* 1 */ [ __NR_write ] = "write",
/* 2 */ [ __NR_open ] = "open",
/* 3 */ [ __NR_close ] = "close",
/* 4 */ [ __NR_stat ] = "stat",
/* 5 */ [ __NR_fstat ] = "fstat",
/* 6 */ [ __NR_lstat ] = "lstat",
/* 7 */ [ __NR_poll ] = "poll",
/* 8 */ [ __NR_lseek ] = "lseek",
/* 9 */ [ __NR_mmap ] = "mmap",
/* 10 */ [ __NR_mprotect ] = "mprotect",
/* 11 */ [ __NR_munmap ] = "munmap",
/* 12 */ [ __NR_brk ] = "brk",
/* 13 */ [ __NR_rt_sigaction ] = "rt_sigaction",
/* 14 */ [ __NR_rt_sigprocmask ] = "rt_sigprocmask",
/* 15 */ [ __NR_rt_sigreturn ] = "rt_sigreturn",
/* 16 */ [ __NR_ioctl ] = "ioctl",
/* 17 */ [ __NR_pread64 ] = "pread64",
/* 18 */ [ __NR_pwrite64 ] = "pwrite64",
/* 19 */ [ __NR_readv ] = "readv",
/* 20 */ [ __NR_writev ] = "writev",
/* 21 */ [ __NR_access ] = "access",
/* 22 */ [ __NR_pipe ] = "pipe",
/* 23 */ [ __NR_select ] = "select",
/* 24 */ [ __NR_sched_yield ] = "sched_yield",
/* 25 */ [ __NR_mremap ] = "mremap",
/* 26 */ [ __NR_msync ] = "msync",
/* 27 */ [ __NR_mincore ] = "mincore",
/* 28 */ [ __NR_madvise ] = "madvise",
/* 29 */ [ __NR_shmget ] = "shmget",
/* 30 */ [ __NR_shmat ] = "shmat",
/* 31 */ [ __NR_shmctl ] = "shmctl",
/* 32 */ [ __NR_dup ] = "dup",
/* 33 */ [ __NR_dup2 ] = "dup2",
/* 34 */ [ __NR_pause ] = "pause",
/* 35 */ [ __NR_nanosleep ] = "nanosleep",
/* 36 */ [ __NR_getitimer ] = "getitimer",
/* 37 */ [ __NR_alarm ] = "alarm",
/* 38 */ [ __NR_setitimer ] = "setitimer",
/* 39 */ [ __NR_getpid ] = "getpid",
/* 40 */ [ __NR_sendfile ] = "sendfile",
/* 41 */ [ __NR_socket ] = "socket",
/* 42 */ [ __NR_connect ] = "connect",
/* 43 */ [ __NR_accept ] = "accept",
/* 44 */ [ __NR_sendto ] = "sendto",
/* 45 */ [ __NR_recvfrom ] = "recvfrom",
/* 46 */ [ __NR_sendmsg ] = "sendmsg",
/* 47 */ [ __NR_recvmsg ] = "recvmsg",
/* 48 */ [ __NR_shutdown ] = "shutdown",
/* 49 */ [ __NR_bind ] = "bind",
/* 50 */ [ __NR_listen ] = "listen",
/* 51 */ [ __NR_getsockname ] = "getsockname",
/* 52 */ [ __NR_getpeername ] = "getpeername",
/* 53 */ [ __NR_socketpair ] = "socketpair",
/* 54 */ [ __NR_setsockopt ] = "setsockopt",
/* 55 */ [ __NR_getsockopt ] = "getsockopt",
/* 56 */ [ __NR_clone ] = "clone",
/* 57 */ [ __NR_fork ] = "fork",
/* 58 */ [ __NR_vfork ] = "vfork",
/* 59 */ [ __NR_execve ] = "execve",
/* 60 */ [ __NR_exit ] = "exit",
/* 61 */ [ __NR_wait4 ] = "wait4",
/* 62 */ [ __NR_kill ] = "kill",
/* 63 */ [ __NR_uname ] = "uname",
/* 64 */ [ __NR_semget ] = "semget",
/* 65 */ [ __NR_semop ] = "semop",
/* 66 */ [ __NR_semctl ] = "semctl",
/* 67 */ [ __NR_shmdt ] = "shmdt",
/* 68 */ [ __NR_msgget ] = "msgget",
/* 69 */ [ __NR_msgsnd ] = "msgsnd",
/* 70 */ [ __NR_msgrcv ] = "msgrcv",
/* 71 */ [ __NR_msgctl ] = "msgctl",
/* 72 */ [ __NR_fcntl ] = "fcntl",
/* 73 */ [ __NR_flock ] = "flock",
/* 74 */ [ __NR_fsync ] = "fsync",
/* 75 */ [ __NR_fdatasync ] = "fdatasync",
/* 76 */ [ __NR_truncate ] = "truncate",
/* 77 */ [ __NR_ftruncate ] = "ftruncate",
/* 78 */ [ __NR_getdents ] = "getdents",
/* 79 */ [ __NR_getcwd ] = "getcwd",
/* 80 */ [ __NR_chdir ] = "chdir",
/* 81 */ [ __NR_fchdir ] = "fchdir",
/* 82 */ [ __NR_rename ] = "rename",
/* 83 */ [ __NR_mkdir ] = "mkdir",
/* 84 */ [ __NR_rmdir ] = "rmdir",
/* 85 */ [ __NR_creat ] = "creat",
/* 86 */ [ __NR_link ] = "link",
/* 87 */ [ __NR_unlink ] = "unlink",
/* 88 */ [ __NR_symlink ] = "symlink",
/* 89 */ [ __NR_readlink ] = "readlink",
/* 90 */ [ __NR_chmod ] = "chmod",
/* 91 */ [ __NR_fchmod ] = "fchmod",
/* 92 */ [ __NR_chown ] = "chown",
/* 93 */ [ __NR_fchown ] = "fchown",
/* 94 */ [ __NR_lchown ] = "lchown",
/* 95 */ [ __NR_umask ] = "umask",
/* 96 */ [ __NR_gettimeofday ] = "gettimeofday",
/* 97 */ [ __NR_getrlimit ] = "getrlimit",
/* 98 */ [ __NR_getrusage ] = "getrusage",
/* 99 */ [ __NR_sysinfo ] = "sysinfo",
/* 100 */ [ __NR_times ] = "times",
/* 101 */ [ __NR_ptrace ] = "ptrace",
/* 102 */ [ __NR_getuid ] = "getuid",
/* 103 */ [ __NR_syslog ] = "syslog",
/* 104 */ [ __NR_getgid ] = "getgid",
/* 105 */ [ __NR_setuid ] = "setuid",
/* 106 */ [ __NR_setgid ] = "setgid",
/* 107 */ [ __NR_geteuid ] = "geteuid",
/* 108 */ [ __NR_getegid ] = "getegid",
/* 109 */ [ __NR_setpgid ] = "setpgid",
/* 110 */ [ __NR_getppid ] = "getppid",
/* 111 */ [ __NR_getpgrp ] = "getpgrp",
/* 112 */ [ __NR_setsid ] = "setsid",
/* 113 */ [ __NR_setreuid ] = "setreuid",
/* 114 */ [ __NR_setregid ] = "setregid",
/* 115 */ [ __NR_getgroups ] = "getgroups",
/* 116 */ [ __NR_setgroups ] = "setgroups",
/* 117 */ [ __NR_setresuid ] = "setresuid",
/* 118 */ [ __NR_getresuid ] = "getresuid",
/* 119 */ [ __NR_setresgid ] = "setresgid",
/* 120 */ [ __NR_getresgid ] = "getresgid",
/* 121 */ [ __NR_getpgid ] = "getpgid",
/* 122 */ [ __NR_setfsuid ] = "setfsuid",
/* 123 */ [ __NR_setfsgid ] = "setfsgid",
/* 124 */ [ __NR_getsid ] = "getsid",
/* 125 */ [ __NR_capget ] = "capget",
/* 126 */ [ __NR_capset ] = "capset",
/* 127 */ [ __NR_rt_sigpending ] = "rt_sigpending",
/* 128 */ [ __NR_rt_sigtimedwait ] = "rt_sigtimedwait",
/* 129 */ [ __NR_rt_sigqueueinfo ] = "rt_sigqueueinfo",
/* 130 */ [ __NR_rt_sigsuspend ] = "rt_sigsuspend",
/* 131 */ [ __NR_sigaltstack ] = "sigaltstack",
/* 132 */ [ __NR_utime ] = "utime",
/* 133 */ [ __NR_mknod ] = "mknod",
/* 134 */ [ __NR_uselib ] = "uselib",
/* 135 */ [ __NR_personality ] = "personality",
/* 136 */ [ __NR_ustat ] = "ustat",
/* 137 */ [ __NR_statfs ] = "statfs",
/* 138 */ [ __NR_fstatfs ] = "fstatfs",
/* 139 */ [ __NR_sysfs ] = "sysfs",
/* 140 */ [ __NR_getpriority ] = "getpriority",
/* 141 */ [ __NR_setpriority ] = "setpriority",
/* 142 */ [ __NR_sched_setparam ] = "sched_setparam",
/* 143 */ [ __NR_sched_getparam ] = "sched_getparam",
/* 144 */ [ __NR_sched_setscheduler ] = "sched_setscheduler",
/* 145 */ [ __NR_sched_getscheduler ] = "sched_getscheduler",
/* 146 */ [ __NR_sched_get_priority_max ] = "sched_get_priority_max",
/* 147 */ [ __NR_sched_get_priority_min ] = "sched_get_priority_min",
/* 148 */ [ __NR_sched_rr_get_interval ] = "sched_rr_get_interval",
/* 149 */ [ __NR_mlock ] = "mlock",
/* 150 */ [ __NR_munlock ] = "munlock",
/* 151 */ [ __NR_mlockall ] = "mlockall",
/* 152 */ [ __NR_munlockall ] = "munlockall",
/* 153 */ [ __NR_vhangup ] = "vhangup",
/* 154 */ [ __NR_modify_ldt ] = "modify_ldt",
/* 155 */ [ __NR_pivot_root ] = "pivot_root",
/* 156 */ [ __NR__sysctl ] = "_sysctl",
/* 157 */ [ __NR_prctl ] = "prctl",
/* 158 */ [ __NR_arch_prctl ] = "arch_prctl",
/* 159 */ [ __NR_adjtimex ] = "adjtimex",
/* 160 */ [ __NR_setrlimit ] = "setrlimit",
/* 161 */ [ __NR_chroot ] = "chroot",
/* 162 */ [ __NR_sync ] = "sync",
/* 163 */ [ __NR_acct ] = "acct",
/* 164 */ [ __NR_settimeofday ] = "settimeofday",
/* 165 */ [ __NR_mount ] = "mount",
/* 166 */ [ __NR_umount2 ] = "umount2",
/* 167 */ [ __NR_swapon ] = "swapon",
/* 168 */ [ __NR_swapoff ] = "swapoff",
/* 169 */ [ __NR_reboot ] = "reboot",
/* 170 */ [ __NR_sethostname ] = "sethostname",
/* 171 */ [ __NR_setdomainname ] = "setdomainname",
/* 172 */ [ __NR_iopl ] = "iopl",
/* 173 */ [ __NR_ioperm ] = "ioperm",
/* 174 */ [ __NR_create_module ] = "create_module",
/* 175 */ [ __NR_init_module ] = "init_module",
/* 176 */ [ __NR_delete_module ] = "delete_module",
/* 177 */ [ __NR_get_kernel_syms ] = "get_kernel_syms",
/* 178 */ [ __NR_query_module ] = "query_module",
/* 179 */ [ __NR_quotactl ] = "quotactl",
/* 180 */ [ __NR_nfsservctl ] = "nfsservctl",
/* 181 */ [ __NR_getpmsg ] = "getpmsg",
/* 182 */ [ __NR_putpmsg ] = "putpmsg",
/* 183 */ [ __NR_afs_syscall ] = "afs_syscall",
/* 184 */ [ __NR_tuxcall ] = "tuxcall",
/* 185 */ [ __NR_security ] = "security",
/* 186 */ [ __NR_gettid ] = "gettid",
/* 187 */ [ __NR_readahead ] = "readahead",
/* 188 */ [ __NR_setxattr ] = "setxattr",
/* 189 */ [ __NR_lsetxattr ] = "lsetxattr",
/* 190 */ [ __NR_fsetxattr ] = "fsetxattr",
/* 191 */ [ __NR_getxattr ] = "getxattr",
/* 192 */ [ __NR_lgetxattr ] = "lgetxattr",
/* 193 */ [ __NR_fgetxattr ] = "fgetxattr",
/* 194 */ [ __NR_listxattr ] = "listxattr",
/* 195 */ [ __NR_llistxattr ] = "llistxattr",
/* 196 */ [ __NR_flistxattr ] = "flistxattr",
/* 197 */ [ __NR_removexattr ] = "removexattr",
/* 198 */ [ __NR_lremovexattr ] = "lremovexattr",
/* 199 */ [ __NR_fremovexattr ] = "fremovexattr",
/* 200 */ [ __NR_tkill ] = "tkill",
/* 201 */ [ __NR_time ] = "time",
/* 202 */ [ __NR_futex ] = "futex",
/* 203 */ [ __NR_sched_setaffinity ] = "sched_setaffinity",
/* 204 */ [ __NR_sched_getaffinity ] = "sched_getaffinity",
/* 205 */ [ __NR_set_thread_area ] = "set_thread_area",
/* 206 */ [ __NR_io_setup ] = "io_setup",
/* 207 */ [ __NR_io_destroy ] = "io_destroy",
/* 208 */ [ __NR_io_getevents ] = "io_getevents",
/* 209 */ [ __NR_io_submit ] = "io_submit",
/* 210 */ [ __NR_io_cancel ] = "io_cancel",
/* 211 */ [ __NR_get_thread_area ] = "get_thread_area",
/* 212 */ [ __NR_lookup_dcookie ] = "lookup_dcookie",
/* 213 */ [ __NR_epoll_create ] = "epoll_create",
/* 214 */ [ __NR_epoll_ctl_old ] = "epoll_ctl_old",
/* 215 */ [ __NR_epoll_wait_old ] = "epoll_wait_old",
/* 216 */ [ __NR_remap_file_pages ] = "remap_file_pages",
/* 217 */ [ __NR_getdents64 ] = "getdents64",
/* 218 */ [ __NR_set_tid_address ] = "set_tid_address",
/* 219 */ [ __NR_restart_syscall ] = "restart_syscall",
/* 220 */ [ __NR_semtimedop ] = "semtimedop",
/* 221 */ [ __NR_fadvise64 ] = "fadvise64",
/* 222 */ [ __NR_timer_create ] = "timer_create",
/* 223 */ [ __NR_timer_settime ] = "timer_settime",
/* 224 */ [ __NR_timer_gettime ] = "timer_gettime",
/* 225 */ [ __NR_timer_getoverrun ] = "timer_getoverrun",
/* 226 */ [ __NR_timer_delete ] = "timer_delete",
/* 227 */ [ __NR_clock_settime ] = "clock_settime",
/* 228 */ [ __NR_clock_gettime ] = "clock_gettime",
/* 229 */ [ __NR_clock_getres ] = "clock_getres",
/* 230 */ [ __NR_clock_nanosleep ] = "clock_nanosleep",
/* 231 */ [ __NR_exit_group ] = "exit_group",
/* 232 */ [ __NR_epoll_wait ] = "epoll_wait",
/* 233 */ [ __NR_epoll_ctl ] = "epoll_ctl",
/* 234 */ [ __NR_tgkill ] = "tgkill",
/* 235 */ [ __NR_utimes ] = "utimes",
/* 236 */ [ __NR_vserver ] = "vserver",
/* 237 */ [ __NR_mbind ] = "mbind",
/* 238 */ [ __NR_set_mempolicy ] = "set_mempolicy",
/* 239 */ [ __NR_get_mempolicy ] = "get_mempolicy",
/* 240 */ [ __NR_mq_open ] = "mq_open",
/* 241 */ [ __NR_mq_unlink ] = "mq_unlink",
/* 242 */ [ __NR_mq_timedsend ] = "mq_timedsend",
/* 243 */ [ __NR_mq_timedreceive ] = "mq_timedreceive",
/* 244 */ [ __NR_mq_notify ] = "mq_notify",
/* 245 */ [ __NR_mq_getsetattr ] = "mq_getsetattr",
/* 246 */ [ __NR_kexec_load ] = "kexec_load",
/* 247 */ [ __NR_waitid ] = "waitid",
/* 248 */ [ __NR_add_key ] = "add_key",
/* 249 */ [ __NR_request_key ] = "request_key",
/* 250 */ [ __NR_keyctl ] = "keyctl",
/* 251 */ [ __NR_ioprio_set ] = "ioprio_set",
/* 252 */ [ __NR_ioprio_get ] = "ioprio_get",
/* 253 */ [ __NR_inotify_init ] = "inotify_init",
/* 254 */ [ __NR_inotify_add_watch ] = "inotify_add_watch",
/* 255 */ [ __NR_inotify_rm_watch ] = "inotify_rm_watch",
/* 256 */ [ __NR_migrate_pages ] = "migrate_pages",
/* 257 */ [ __NR_openat ] = "openat",
/* 258 */ [ __NR_mkdirat ] = "mkdirat",
/* 259 */ [ __NR_mknodat ] = "mknodat",
/* 260 */ [ __NR_fchownat ] = "fchownat",
/* 261 */ [ __NR_futimesat ] = "futimesat",
/* 262 */ [ __NR_newfstatat ] = "newfstatat",
/* 263 */ [ __NR_unlinkat ] = "unlinkat",
/* 264 */ [ __NR_renameat ] = "renameat",
/* 265 */ [ __NR_linkat ] = "linkat",
/* 266 */ [ __NR_symlinkat ] = "symlinkat",
/* 267 */ [ __NR_readlinkat ] = "readlinkat",
/* 268 */ [ __NR_fchmodat ] = "fchmodat",
/* 269 */ [ __NR_faccessat ] = "faccessat",
/* 270 */ [ __NR_pselect6 ] = "pselect6",
/* 271 */ [ __NR_ppoll ] = "ppoll",
/* 272 */ [ __NR_unshare ] = "unshare",
/* 273 */ [ __NR_set_robust_list ] = "set_robust_list",
/* 274 */ [ __NR_get_robust_list ] = "get_robust_list",
/* 275 */ [ __NR_splice ] = "splice",
/* 276 */ [ __NR_tee ] = "tee",
/* 277 */ [ __NR_sync_file_range ] = "sync_file_range",
/* 278 */ [ __NR_vmsplice ] = "vmsplice",
/* 279 */ [ __NR_move_pages ] = "move_pages",
/* 280 */ [ __NR_utimensat ] = "utimensat",
/* 281 */ [ __NR_epoll_pwait ] = "epoll_pwait",
/* 282 */ [ __NR_signalfd ] = "signalfd",
/* 283 */ [ __NR_timerfd_create ] = "timerfd_create",
/* 284 */ [ __NR_eventfd ] = "eventfd",
/* 285 */ [ __NR_fallocate ] = "fallocate",
/* 286 */ [ __NR_timerfd_settime ] = "timerfd_settime",
/* 287 */ [ __NR_timerfd_gettime ] = "timerfd_gettime",
/* 288 */ [ __NR_accept4 ] = "accept4",
/* 289 */ [ __NR_signalfd4 ] = "signalfd4",
/* 290 */ [ __NR_eventfd2 ] = "eventfd2",
/* 291 */ [ __NR_epoll_create1 ] = "epoll_create1",
/* 292 */ [ __NR_dup3 ] = "dup3",
/* 293 */ [ __NR_pipe2 ] = "pipe2",
/* 294 */ [ __NR_inotify_init1 ] = "inotify_init1",
/* 295 */ [ __NR_preadv ] = "preadv",
/* 296 */ [ __NR_pwritev ] = "pwritev",
/* 297 */ [ __NR_rt_tgsigqueueinfo ] = "rt_tgsigqueueinfo",
/* 298 */ [ __NR_perf_event_open ] = "perf_event_open",
/* 299 */ [ __NR_recvmmsg ] = "recvmmsg",
/* 300 */ [ __NR_fanotify_init ] = "fanotify_init",
/* 301 */ [ __NR_fanotify_mark ] = "fanotify_mark",
/* 302 */ [ __NR_prlimit64 ] = "prlimit64",
/* 303 */ [ __NR_name_to_handle_at ] = "name_to_handle_at",
/* 304 */ [ __NR_open_by_handle_at ] = "open_by_handle_at",
/* 305 */ [ __NR_clock_adjtime ] = "clock_adjtime",
/* 306 */ [ __NR_syncfs ] = "syncfs",
/* 307 */ [ __NR_sendmmsg ] = "sendmmsg",
/* 308 */ [ __NR_setns ] = "setns",
/* 309 */ [ __NR_getcpu ] = "getcpu",
/* 310 */ [ __NR_process_vm_readv ] = "process_vm_readv",
/* 311 */ [ __NR_process_vm_writev ] = "process_vm_writev",
/* 312 */ [ __NR_kcmp ] = "kcmp",
/* 313 */ [ __NR_finit_module ] = "finit_module",
};
#define NUM_SYSCALLS ARRAY_SIZE(syscall_names)
#define NUM_ACTIONS (NUM_SYSCALLS+64)

enum action {
  A_DEFAULT,		// Use the default action
  A_NO,			// Always forbid
  A_YES,		// Always permit
  A_FILENAME,		// Permit if arg1 is a known filename
  A_ACTION_MASK = 15,
  A_NO_RETVAL = 32,	// Does not return a value
  A_SAMPLE_MEM = 64,	// Sample memory usage before the syscall
  A_LIBERAL = 128,	// Valid only in liberal mode
  // Must fit in a unsigned char
};

static unsigned char syscall_action[NUM_ACTIONS] = {
#define S(x) [__NR_##x]

    // Syscalls permitted for specific file names
    S(open) = A_FILENAME,
    S(creat) = A_FILENAME,
    S(unlink) = A_FILENAME,
    S(access) = A_FILENAME,			
    S(truncate) = A_FILENAME,
    S(stat) = A_FILENAME,
    S(lstat) = A_FILENAME,
    S(readlink) = A_FILENAME,
#ifndef CONFIG_BOX_USER_AMD64
    S(oldstat) = A_FILENAME,
    S(oldlstat) = A_FILENAME,
    S(truncate64) = A_FILENAME,
    S(stat64) = A_FILENAME,
    S(lstat64) = A_FILENAME,
#endif

    // Syscalls permitted always
    S(exit) = A_YES | A_SAMPLE_MEM,
    S(read) = A_YES,
    S(write) = A_YES,
    S(close) = A_YES,
    S(lseek) = A_YES,
    S(getpid) = A_YES,
    S(getuid) = A_YES,
    S(dup) = A_YES,
    S(brk) = A_YES,
    S(getgid) = A_YES,
    S(geteuid) = A_YES,
    S(getegid) = A_YES,
    S(dup2) = A_YES,
    S(ftruncate) = A_YES,
    S(fstat) = A_YES,
    S(personality) = A_YES,
    S(readv) = A_YES,
    S(writev) = A_YES,
    S(getresuid) = A_YES,
#ifdef __NR_pread64
    S(pread64) = A_YES,
    S(pwrite64) = A_YES,
#else
    S(pread) = A_YES,
    S(pwrite) = A_YES,
#endif
    S(fcntl) = A_YES,
    S(mmap) = A_YES,
    S(munmap) = A_YES,
    S(ioctl) = A_YES,
    S(uname) = A_YES,
    S(gettid) = A_YES,
    S(set_thread_area) = A_YES,
    S(get_thread_area) = A_YES,
    S(set_tid_address) = A_YES,
    S(exit_group) = A_YES | A_SAMPLE_MEM,
#ifdef CONFIG_BOX_USER_AMD64
    S(arch_prctl) = A_YES,
#else
    S(oldfstat) = A_YES,
    S(ftruncate64) = A_YES,
    S(_llseek) = A_YES,
    S(fstat64) = A_YES,
    S(fcntl64) = A_YES,
    S(mmap2) = A_YES,
#endif

    // Syscalls permitted only in liberal mode
    S(time) = A_YES | A_LIBERAL,
    S(alarm) = A_YES | A_LIBERAL,
    S(pause) = A_YES | A_LIBERAL,
    S(fchmod) = A_YES | A_LIBERAL,
    S(getrlimit) = A_YES | A_LIBERAL,
    S(getrusage) = A_YES | A_LIBERAL,
    S(gettimeofday) = A_YES | A_LIBERAL,
    S(select) = A_YES | A_LIBERAL,
    S(setitimer) = A_YES | A_LIBERAL,
    S(getitimer) = A_YES | A_LIBERAL,
    S(mprotect) = A_YES | A_LIBERAL,
    S(getdents) = A_YES | A_LIBERAL,
    S(getdents64) = A_YES | A_LIBERAL,
    S(fdatasync) = A_YES | A_LIBERAL,
    S(mremap) = A_YES | A_LIBERAL,
    S(poll) = A_YES | A_LIBERAL,
    S(getcwd) = A_YES | A_LIBERAL,
    S(nanosleep) = A_YES | A_LIBERAL,
    S(rt_sigreturn) = A_YES | A_LIBERAL | A_NO_RETVAL,
    S(rt_sigaction) = A_YES | A_LIBERAL,
    S(rt_sigprocmask) = A_YES | A_LIBERAL,
    S(rt_sigpending) = A_YES | A_LIBERAL,
    S(rt_sigtimedwait) = A_YES | A_LIBERAL,
    S(rt_sigqueueinfo) = A_YES | A_LIBERAL,
    S(rt_sigsuspend) = A_YES | A_LIBERAL,
    S(_sysctl) = A_YES | A_LIBERAL,
#ifndef CONFIG_BOX_USER_AMD64
    S(sigaction) = A_YES | A_LIBERAL,
    S(sgetmask) = A_YES | A_LIBERAL,
    S(ssetmask) = A_YES | A_LIBERAL,
    S(sigsuspend) = A_YES | A_LIBERAL,
    S(sigpending) = A_YES | A_LIBERAL,
    S(sigreturn) = A_YES | A_LIBERAL | A_NO_RETVAL,
    S(sigprocmask) = A_YES | A_LIBERAL,
    S(ugetrlimit) = A_YES | A_LIBERAL,
    S(readdir) = A_YES | A_LIBERAL,
    S(signal) = A_YES | A_LIBERAL,
    S(_newselect) = A_YES | A_LIBERAL,
#endif

#undef S
};

static const char *
syscall_name(unsigned int id, char *buf)
{
  if (id < NUM_SYSCALLS && syscall_names[id])
    return syscall_names[id];
  else
    {
      sprintf(buf, "#%d", id);
      return buf;
    }
}

static int
syscall_by_name(char *name)
{
  for (unsigned int i=0; i<NUM_SYSCALLS; i++)
    if (syscall_names[i] && !strcmp(syscall_names[i], name))
      return i;
  if (name[0] == '#')
    name++;
  if (!*name)
    return -1;
  char *ep;
  unsigned long l = strtoul(name, &ep, 0);
  if (*ep)
    return -1;
  if (l >= NUM_ACTIONS)
    return NUM_ACTIONS;
  return l;
}

static int
set_syscall_action(char *a)
{
  char *sep = strchr(a, '=');
  enum action act = A_YES;
  if (sep)
    {
      *sep++ = 0;
      if (!strcmp(sep, "yes"))
	act = A_YES;
      else if (!strcmp(sep, "no"))
	act = A_NO;
      else if (!strcmp(sep, "file"))
	act = A_FILENAME;
      else
	return 0;
    }

  int sys = syscall_by_name(a);
  if (sys < 0)
    die("Unknown syscall `%s'", a);
  if (sys >= NUM_ACTIONS)
    die("Syscall `%s' out of range", a);
  syscall_action[sys] = act;
  return 1;
}

/*** Path rules ***/

struct path_rule {
  char *path;
  enum action action;
  struct path_rule *next;
};

static struct path_rule default_path_rules[] = {
  { "/etc/", A_YES },
  { "/lib/", A_YES },
  { "/usr/lib/", A_YES },
  { "/opt/lib/", A_YES },
  { "/usr/share/zoneinfo/", A_YES },
  { "/usr/share/locale/", A_YES },
  { "/dev/null", A_YES },
  { "/dev/zero", A_YES },
  { "/proc/meminfo", A_YES },
  { "/proc/self/stat", A_YES },
  { "/proc/self/exe", A_YES },			// Needed by FPC 2.0.x runtime
  { "/proc/self/maps", A_YES },			// Needed by glibc when it reports arena corruption
};

static struct path_rule *user_path_rules;
static struct path_rule **last_path_rule = &user_path_rules;

static int
set_path_action(char *a)
{
  char *sep = strchr(a, '=');
  enum action act = A_YES;
  if (sep)
    {
      *sep++ = 0;
      if (!strcmp(sep, "yes"))
	act = A_YES;
      else if (!strcmp(sep, "no"))
	act = A_NO;
      else
	return 0;
    }

  struct path_rule *r = xmalloc(sizeof(*r) + strlen(a) + 1);
  r->path = (char *)(r+1);
  strcpy(r->path, a);
  r->action = act;
  r->next = NULL;
  *last_path_rule = r;
  last_path_rule = &r->next;
  return 1;
}

static enum action
match_path_rule(struct path_rule *r, char *path)
{
  char *rr = r->path;
  while (*rr)
    if (*rr++ != *path++)
      {
	if (rr[-1] == '/' && !path[-1])
	  break;
	return A_DEFAULT;
      }
  if (rr > r->path && rr[-1] != '/' && *path)
    return A_DEFAULT;
  return r->action;
}

/*** Environment rules ***/

struct env_rule {
  char *var;			// Variable to match
  char *val;			// ""=clear, NULL=inherit
  int var_len;
  struct env_rule *next;
};

static struct env_rule *first_env_rule;
static struct env_rule **last_env_rule = &first_env_rule;

static struct env_rule default_env_rules[] = {
  { "LIBC_FATAL_STDERR_", "1" }
};

static int
set_env_action(char *a0)
{
  struct env_rule *r = xmalloc(sizeof(*r) + strlen(a0) + 1);
  char *a = (char *)(r+1);
  strcpy(a, a0);

  char *sep = strchr(a, '=');
  if (sep == a)
    return 0;
  r->var = a;
  if (sep)
    {
      *sep++ = 0;
      r->val = sep;
    }
  else
    r->val = NULL;
  *last_env_rule = r;
  last_env_rule = &r->next;
  r->next = NULL;
  return 1;
}

static int
match_env_var(char *env_entry, struct env_rule *r)
{
  if (strncmp(env_entry, r->var, r->var_len))
    return 0;
  return (env_entry[r->var_len] == '=');
}

static void
apply_env_rule(char **env, int *env_sizep, struct env_rule *r)
{
  // First remove the variable if already set
  int pos = 0;
  while (pos < *env_sizep && !match_env_var(env[pos], r))
    pos++;
  if (pos < *env_sizep)
    {
      (*env_sizep)--;
      env[pos] = env[*env_sizep];
      env[*env_sizep] = NULL;
    }

  // What is the new value?
  char *new;
  if (r->val)
    {
      if (!r->val[0])
	return;
      new = xmalloc(r->var_len + 1 + strlen(r->val) + 1);
      sprintf(new, "%s=%s", r->var, r->val);
    }
  else
    {
      pos = 0;
      while (environ[pos] && !match_env_var(environ[pos], r))
	pos++;
      if (!(new = environ[pos]))
	return;
    }

  // Add it at the end of the array
  env[(*env_sizep)++] = new;
  env[*env_sizep] = NULL;
}

static char **
setup_environment(void)
{
  // Link built-in rules with user rules
  for (int i=ARRAY_SIZE(default_env_rules)-1; i >= 0; i--)
    {
      default_env_rules[i].next = first_env_rule;
      first_env_rule = &default_env_rules[i];
    }

  // Scan the original environment
  char **orig_env = environ;
  int orig_size = 0;
  while (orig_env[orig_size])
    orig_size++;

  // For each rule, reserve one more slot and calculate length
  int num_rules = 0;
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    {
      num_rules++;
      r->var_len = strlen(r->var);
    }

  // Create a new environment
  char **env = xmalloc((orig_size + num_rules + 1) * sizeof(char *));
  int size;
  if (pass_environ)
    {
      memcpy(env, environ, orig_size * sizeof(char *));
      size = orig_size;
    }
  else
    size = 0;
  env[size] = NULL;

  // Apply the rules one by one
  for (struct env_rule *r = first_env_rule; r; r=r->next)
    apply_env_rule(env, &size, r);

  // Return the new env and pass some gossip
  if (verbose > 1)
    {
      fprintf(stderr, "Passing environment:\n");
      for (int i=0; env[i]; i++)
	fprintf(stderr, "\t%s\n", env[i]);
    }
  return env;
}

/*** Low-level parsing of syscalls ***/

#ifdef CONFIG_BOX_KERNEL_AMD64
typedef uint64_t arg_t;
#else
typedef uint32_t arg_t;
#endif

struct syscall_args {
  arg_t sys;
  arg_t arg1, arg2, arg3;
  arg_t result;
  struct user user;
};

static int user_mem_fd;

static int read_user_mem(arg_t addr, char *buf, int len)
{
  if (!user_mem_fd)
    {
      char memname[64];
      sprintf(memname, "/proc/%d/mem", (int) box_pid);
      user_mem_fd = open(memname, O_RDONLY);
      if (user_mem_fd < 0)
	die("open(%s): %m", memname);
    }
  if (lseek64(user_mem_fd, addr, SEEK_SET) < 0)
    die("lseek64(mem): %m");
  return read(user_mem_fd, buf, len);
}

static void close_user_mem(void)
{
  if (user_mem_fd)
    {
      close(user_mem_fd);
      user_mem_fd = 0;
    }
}

#ifdef CONFIG_BOX_KERNEL_AMD64

static void
get_syscall_args(struct syscall_args *a, int is_exit)
{
  if (ptrace(PTRACE_GETREGS, box_pid, NULL, &a->user) < 0)
    die("ptrace(PTRACE_GETREGS): %m");
  a->sys = a->user.regs.orig_rax;
  a->result = a->user.regs.rax;

  /*
   *  CAVEAT: We have to check carefully that this is a real 64-bit syscall.
   *  We test whether the process runs in 64-bit mode, but surprisingly this
   *  is not enough: a 64-bit process can still issue the INT 0x80 instruction
   *  which performs a 32-bit syscall. Currently, the only known way how to
   *  detect this situation is to inspect the instruction code (the kernel
   *  keeps a syscall type flag internally, but it is not accessible from
   *  user space). Hopefully, there is no instruction whose suffix is the
   *  code of the SYSCALL instruction. Sometimes, one would wish the
   *  instruction codes to be unique even when read backwards :)
   */

  if (is_exit)
    return;

  int sys_type;
  uint16_t instr;

  switch (a->user.regs.cs)
    {
    case 0x23:
      // 32-bit CPU mode => only 32-bit syscalls can be issued
      sys_type = 32;
      break;
    case 0x33:
      // 64-bit CPU mode
      if (read_user_mem(a->user.regs.rip-2, (char *) &instr, 2) != 2)
	err("FO: Cannot read syscall instruction");
      switch (instr)
	{
	case 0x050f:
	  break;
	case 0x80cd:
	  err("FO: Forbidden 32-bit syscall in 64-bit mode");
	default:
	  err("XX: Unknown syscall instruction %04x", instr);
	}
      sys_type = 64;
      break;
    default:
      err("XX: Unknown code segment %04jx", (intmax_t) a->user.regs.cs);
    }

#ifdef CONFIG_BOX_USER_AMD64
  if (sys_type != 64)
    err("FO: Forbidden %d-bit mode syscall", sys_type);
#else
  if (sys_type != (exec_seen ? 32 : 64))
    err("FO: Forbidden %d-bit mode syscall", sys_type);
#endif

  if (sys_type == 32)
    {
      a->arg1 = a->user.regs.rbx;
      a->arg2 = a->user.regs.rcx;
      a->arg3 = a->user.regs.rdx;
    }
  else
    {
      a->arg1 = a->user.regs.rdi;
      a->arg2 = a->user.regs.rsi;
      a->arg3 = a->user.regs.rdx;
    }
}

static void
set_syscall_nr(struct syscall_args *a, arg_t sys)
{
  a->sys = sys;
  a->user.regs.orig_rax = sys;
  if (ptrace(PTRACE_SETREGS, box_pid, NULL, &a->user) < 0)
    die("ptrace(PTRACE_SETREGS): %m");
}

static void
sanity_check(void)
{
}

#else

static void
get_syscall_args(struct syscall_args *a, int is_exit UNUSED)
{
  if (ptrace(PTRACE_GETREGS, box_pid, NULL, &a->user) < 0)
    die("ptrace(PTRACE_GETREGS): %m");
  a->sys = a->user.regs.orig_eax;
  a->arg1 = a->user.regs.ebx;
  a->arg2 = a->user.regs.ecx;
  a->arg3 = a->user.regs.edx;
  a->result = a->user.regs.eax;
}

static void
set_syscall_nr(struct syscall_args *a, arg_t sys)
{
  a->sys = sys;
  a->user.regs.orig_eax = sys;
  if (ptrace(PTRACE_SETREGS, box_pid, NULL, &a->user) < 0)
    die("ptrace(PTRACE_SETREGS): %m");
}

static void
sanity_check(void)
{
#if !defined(CONFIG_BOX_ALLOW_INSECURE)
  struct utsname uts;
  if (uname(&uts) < 0)
    die("uname() failed: %m");

  if (!strcmp(uts.machine, "x86_64"))
    die("Running 32-bit sandbox on 64-bit kernels is inherently unsafe. Please get a 64-bit version.");
#endif
}

#endif

/*** Syscall checks ***/

static void
valid_filename(arg_t addr)
{
  char namebuf[4096], *p, *end;

  if (!file_access)
    err("FA: File access forbidden");
  if (file_access >= 9)
    return;

  p = end = namebuf;
  do
    {
      if (p >= end)
	{
	  int remains = PAGE_SIZE - (addr & (PAGE_SIZE-1));
	  int l = namebuf + sizeof(namebuf) - end;
	  if (l > remains)
	    l = remains;
	  if (!l)
	    err("FA: Access to file with name too long");
	  remains = read_user_mem(addr, end, l);
	  if (remains < 0)
	    die("read(mem): %m");
	  if (!remains)
	    err("FA: Access to file with name out of memory");
	  end += remains;
	  addr += remains;
	}
    }
  while (*p++);

  msg("[%s] ", namebuf);
  if (file_access >= 3)
    return;

  // Everything in current directory is permitted
  if (!strchr(namebuf, '/') && strcmp(namebuf, ".."))
    return;

  // ".." anywhere in the path is forbidden
  enum action act = A_DEFAULT;
  if (strstr(namebuf, ".."))
    act = A_NO;

  // Scan user rules
  for (struct path_rule *r = user_path_rules; r && !act; r=r->next)
    act = match_path_rule(r, namebuf);

  // Scan built-in rules
  if (file_access >= 2)
    for (int i=0; i<ARRAY_SIZE(default_path_rules) && !act; i++)
      act = match_path_rule(&default_path_rules[i], namebuf);

  if (act != A_YES)
    err("FA: Forbidden access to file `%s'", namebuf);
}

// Check syscall. If invalid, return -1, otherwise return the action mask.
static int
valid_syscall(struct syscall_args *a)
{
  unsigned int sys = a->sys;
  unsigned int act = (sys < NUM_ACTIONS) ? syscall_action[sys] : A_DEFAULT;

  if (act & A_LIBERAL)
    {
      if (filter_syscalls != 1)
        act = A_DEFAULT;
    }

  switch (act & A_ACTION_MASK)
    {
    case A_YES:
      return act;
    case A_NO:
      return -1;
    case A_FILENAME:
      valid_filename(a->arg1);
      return act;
    default: ;
    }

  switch (sys)
    {
    case __NR_kill:
      if (a->arg1 == (arg_t) box_pid)
	{
	  meta_printf("exitsig:%d\n", (int) a->arg2);
	  err("SG: Committed suicide by signal %d", (int) a->arg2);
	}
      return -1;
    case __NR_tgkill:
      if (a->arg1 == (arg_t) box_pid && a->arg2 == (arg_t) box_pid)
	{
	  meta_printf("exitsig:%d\n", (int) a->arg3);
	  err("SG: Committed suicide by signal %d", (int) a->arg3);
	}
      return -1;
    default:
      return -1;
    }
}

static void
signal_alarm(int unused UNUSED)
{
  /* Time limit checks are synchronous, so we only schedule them there. */
  timer_tick = 1;
  alarm(1);
}

static void
signal_int(int unused UNUSED)
{
  /* Interrupts are fatal, so no synchronization requirements. */
  meta_printf("exitsig:%d\n", SIGINT);
  err("SG: Interrupted");
}

#define PROC_BUF_SIZE 4096
static void
read_proc_file(char *buf, char *name, int *fdp)
{
  int c;

  if (!*fdp)
    {
      sprintf(buf, "/proc/%d/%s", (int) box_pid, name);
      *fdp = open(buf, O_RDONLY);
      if (*fdp < 0)
	die("open(%s): %m", buf);
    }
  lseek(*fdp, 0, SEEK_SET);
  if ((c = read(*fdp, buf, PROC_BUF_SIZE-1)) < 0)
    die("read on /proc/$pid/%s: %m", name);
  if (c >= PROC_BUF_SIZE-1)
    die("/proc/$pid/%s too long", name);
  buf[c] = 0;
}

static void
check_timeout(void)
{
  if (wall_timeout)
    {
      struct timeval now, wall;
      int wall_ms;
      gettimeofday(&now, NULL);
      timersub(&now, &start_time, &wall);
      wall_ms = wall.tv_sec*1000 + wall.tv_usec/1000;
      if (wall_ms > wall_timeout)
        err("TO: Time limit exceeded (wall clock)");
      if (verbose > 1)
        fprintf(stderr, "[wall time check: %d msec]\n", wall_ms);
    }
  if (timeout)
    {
      char buf[PROC_BUF_SIZE], *x;
      int utime, stime, ms;
      static int proc_stat_fd;
      read_proc_file(buf, "stat", &proc_stat_fd);
      x = buf;
      while (*x && *x != ' ')
	x++;
      while (*x == ' ')
	x++;
      if (*x++ != '(')
	die("proc stat syntax error 1");
      while (*x && (*x != ')' || x[1] != ' '))
	x++;
      while (*x == ')' || *x == ' ')
	x++;
      if (sscanf(x, "%*c %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d %d %d", &utime, &stime) != 2)
	die("proc stat syntax error 2");
      ms = (utime + stime) * 1000 / ticks_per_sec;
      if (verbose > 1)
	fprintf(stderr, "[time check: %d msec]\n", ms);
      if (ms > timeout && ms > extra_timeout)
	err("TO: Time limit exceeded");
    }
}

static void
sample_mem_peak(void)
{
  /*
   *  We want to find out the peak memory usage of the process, which is
   *  maintained by the kernel, but unforunately it gets lost when the
   *  process exits (it is not reported in struct rusage). Therefore we
   *  have to sample it whenever we suspect that the process is about
   *  to exit.
   */
  char buf[PROC_BUF_SIZE], *x;
  static int proc_status_fd;
  read_proc_file(buf, "status", &proc_status_fd);

  x = buf;
  while (*x)
    {
      char *key = x;
      while (*x && *x != ':' && *x != '\n')
	x++;
      if (!*x || *x == '\n')
	break;
      *x++ = 0;
      while (*x == ' ' || *x == '\t')
	x++;

      char *val = x;
      while (*x && *x != '\n')
	x++;
      if (!*x)
	break;
      *x++ = 0;

      if (!strcmp(key, "VmPeak"))
	{
	  int peak = atoi(val);
	  if (peak > mem_peak_kb)
	    mem_peak_kb = peak;
	}
    }

  if (verbose > 1)
    msg("[mem-peak: %u KB]\n", mem_peak_kb);
}

static void
boxkeeper(void)
{
  int syscall_count = (filter_syscalls ? 0 : 1);
  struct sigaction sa;

  is_ptraced = 1;

  bzero(&sa, sizeof(sa));
  sa.sa_handler = signal_int;
  sigaction(SIGINT, &sa, NULL);

  gettimeofday(&start_time, NULL);
  ticks_per_sec = sysconf(_SC_CLK_TCK);
  if (ticks_per_sec <= 0)
    die("Invalid ticks_per_sec!");

  if (timeout || wall_timeout)
    {
      sa.sa_handler = signal_alarm;
      sigaction(SIGALRM, &sa, NULL);
      alarm(1);
    }

  for(;;)
    {
      struct rusage rus;
      int stat;
      pid_t p;
      if (timer_tick)
	{
	  check_timeout();
	  timer_tick = 0;
	}
      p = wait4(box_pid, &stat, WUNTRACED, &rus);
      if (p < 0)
	{
	  if (errno == EINTR)
	    continue;
	  die("wait4: %m");
	}
      if (p != box_pid)
	die("wait4: unknown pid %d exited!", p);
      if (WIFEXITED(stat))
	{
	  box_pid = 0;
	  final_stats(&rus);
	  if (WEXITSTATUS(stat))
	    {
	      if (syscall_count)
		{
		  meta_printf("exitcode:%d\n", WEXITSTATUS(stat));
		  err("RE: Exited with error status %d", WEXITSTATUS(stat));
		}
	      else
		{
		  // Internal error happened inside the child process and it has been already reported.
		  box_exit(2);
		}
	    }
	  if (timeout && total_ms > timeout)
	    err("TO: Time limit exceeded");
	  if (wall_timeout && wall_ms > wall_timeout)
	    err("TO: Time limit exceeded (wall clock)");
	  flush_line();
    fprintf(stderr,"OK\n");
	  box_exit(0);
	}
      if (WIFSIGNALED(stat))
	{
	  box_pid = 0;
	  meta_printf("exitsig:%d\n", WTERMSIG(stat));
	  final_stats(&rus);
	  err("SG: Caught fatal signal %d%s", WTERMSIG(stat), (syscall_count ? "" : " during startup"));
	}
      if (WIFSTOPPED(stat))
	{
	  int sig = WSTOPSIG(stat);
	  if (sig == SIGTRAP)
	    {
	      if (verbose > 2)
		msg("[ptrace status %08x] ", stat);
	      static int stop_count;
	      if (!stop_count++)		/* Traceme request */
		msg(">> Traceme request caught\n");
	      else
		err("SG: Breakpoint");
	      ptrace(PTRACE_SYSCALL, box_pid, 0, 0);
	    }
	  else if (sig == (SIGTRAP | 0x80))
	    {
	      if (verbose > 2)
		msg("[ptrace status %08x] ", stat);
	      struct syscall_args a;
	      static unsigned int sys_tick, last_act;
	      static arg_t last_sys;
	      if (++sys_tick & 1)		/* Syscall entry */
		{
		  char namebuf[32];
		  int act;

		  get_syscall_args(&a, 0);
		  arg_t sys = a.sys;
		  msg(">> Syscall %-12s (%08jx,%08jx,%08jx) ", syscall_name(sys, namebuf), (intmax_t) a.arg1, (intmax_t) a.arg2, (intmax_t) a.arg3);
		  if (!exec_seen)
		    {
		      msg("[master] ");
		      if (sys == NATIVE_NR_execve)
			{
			  exec_seen = 1;
			  close_user_mem();
			}
		    }
		  else if ((act = valid_syscall(&a)) >= 0)
		    {
		      last_act = act;
		      syscall_count++;
		      if (act & A_SAMPLE_MEM)
			sample_mem_peak();
		    }
		  else
		    {
		      /*
		       * Unfortunately, PTRACE_KILL kills _after_ the syscall completes,
		       * so we have to change it to something harmless (e.g., an undefined
		       * syscall) and make the program continue.
		       */
		      set_syscall_nr(&a, ~(arg_t)0);
		      err("FO: Forbidden syscall %s", syscall_name(sys, namebuf));
		    }
		  last_sys = sys;
		}
	      else					/* Syscall return */
		{
		  get_syscall_args(&a, 1);
		  if (a.sys == ~(arg_t)0)
		    {
		      /* Some syscalls (sigreturn et al.) do not return a value */
		      if (!(last_act & A_NO_RETVAL))
			err("XX: Syscall does not return, but it should");
		    }
		  else
		    {
		      if (a.sys != last_sys)
			err("XX: Mismatched syscall entry/exit");
		    }
		  if (last_act & A_NO_RETVAL)
		    msg("= ?\n");
		  else
		    msg("= %jd\n", (intmax_t) a.result);
		}
	      ptrace(PTRACE_SYSCALL, box_pid, 0, 0);
	    }
	  else if (sig == SIGSTOP)
	    {
	      msg(">> SIGSTOP\n");
	      if (ptrace(PTRACE_SETOPTIONS, box_pid, NULL, (void *) PTRACE_O_TRACESYSGOOD) < 0)
		die("ptrace(PTRACE_SETOPTIONS): %m");
	      ptrace(PTRACE_SYSCALL, box_pid, 0, 0);
	    }
	  else if (sig != SIGXCPU && sig != SIGXFSZ)
	    {
	      msg(">> Signal %d\n", sig);
	      sample_mem_peak();			/* Signal might be fatal, so update mem-peak */
	      ptrace(PTRACE_SYSCALL, box_pid, 0, sig);
	    }
	  else
	    {
	      meta_printf("exitsig:%d", sig);
	      err("SG: Received signal %d", sig);
	    }
	}
      else
	die("wait4: unknown status %x, giving up!", stat);
    }
}

static void
box_inside(int argc, char **argv)
{
  struct rlimit rl;
  char *args[argc+1];

  memcpy(args, argv, argc * sizeof(char *));
  args[argc] = NULL;
  if (set_cwd && chdir(set_cwd))
    die("chdir: %m");
  if (redir_stdin)
    {
      close(0);
      if (open(redir_stdin, O_RDONLY) != 0)
	die("open(\"%s\"): %m", redir_stdin);
    }
  if (redir_stdout)
    {
      close(1);
      if (open(redir_stdout, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 1)
	die("open(\"%s\"): %m", redir_stdout);
    }
  if (redir_stderr)
    {
      close(2);
      if (open(redir_stderr, O_WRONLY | O_CREAT | O_TRUNC, 0666) != 2)
	die("open(\"%s\"): %m", redir_stderr);
    }
  else
    dup2(1, 2);
  setpgrp();

  if (memory_limit)
    {
      rl.rlim_cur = rl.rlim_max = memory_limit * 1024;
      if (setrlimit(RLIMIT_AS, &rl) < 0)
	die("setrlimit(RLIMIT_AS): %m");
    }

  rl.rlim_cur = rl.rlim_max = (stack_limit ? (rlim_t)stack_limit * 1024 : RLIM_INFINITY);
  if (setrlimit(RLIMIT_STACK, &rl) < 0)
    die("setrlimit(RLIMIT_STACK): %m");

  rl.rlim_cur = rl.rlim_max = 64;
  if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
    die("setrlimit(RLIMIT_NOFILE): %m");

  char **env = setup_environment();
  if (filter_syscalls)
    {
      if (ptrace(PTRACE_TRACEME) < 0)
	die("ptrace(PTRACE_TRACEME): %m");
      /* Trick: Make sure that we are stopped until the boxkeeper wakes up. */
      raise(SIGSTOP);
    }
  execve(args[0], args, env);
  die("execve(\"%s\"): %m", args[0]);
}

static void
usage(void)
{
  fprintf(stderr, "Invalid arguments!\n");
  printf("\
Usage: box [<options>] -- <command> <arguments>\n\
\n\
Options:\n\
-a <level>\tSet file access level (0=none, 1=cwd, 2=/etc,/lib,..., 3=whole fs, 9=no checks; needs -f)\n\
-c <dir>\tChange directory to <dir> first\n\
-e\t\tInherit full environment of the parent process\n\
-E <var>\tInherit the environment variable <var> from the parent process\n\
-E <var>=<val>\tSet the environment variable <var> to <val>; unset it if <var> is empty\n\
-f\t\tFilter system calls (-ff=very restricted)\n\
-i <file>\tRedirect stdin from <file>\n\
-k <size>\tLimit stack size to <size> KB (default: 0=unlimited)\n\
-m <size>\tLimit address space to <size> KB\n\
-M <file>\tOutput process information to <file> (name:value)\n\
-o <file>\tRedirect stdout to <file>\n\
-p <path>\tPermit access to the specified path (or subtree if it ends with a `/')\n\
-p <path>=<act>\tDefine action for the specified path (<act>=yes/no)\n\
-r <file>\tRedirect stderr to <file>\n\
-s <sys>\tPermit the specified syscall (be careful)\n\
-s <sys>=<act>\tDefine action for the specified syscall (<act>=yes/no/file)\n\
-t <time>\tSet run time limit (seconds, fractions allowed)\n\
-T\t\tAllow syscalls for measuring run time\n\
-v\t\tBe verbose (use multiple times for even more verbosity)\n\
-w <time>\tSet wall clock time limit (seconds, fractions allowed)\n\
-x <time>\tSet extra timeout, before which a timing-out program is not yet killed,\n\
\t\tso that its real execution time is reported (seconds, fractions allowed)\n\
-A <opt>\tPass <opt> as additional argument to the <command>\n\
\t\tBe noted that this option will be appended after <arguments> respectively\n\
");
  exit(2);
}

int
main(int argc, char **argv)
{
  int c;
  uid_t uid;
  char **prog_argv = xmalloc(sizeof(char*) * argc);
  int prog_argc = 0;

  while ((c = getopt(argc, argv, "a:c:eE:fi:k:m:M:o:p:r:s:t:Tvw:x:A:")) >= 0)
    switch (c)
      {
      case 'a':
	file_access = atol(optarg);
	break;
      case 'c':
	set_cwd = optarg;
	break;
      case 'e':
	pass_environ = 1;
	break;
      case 'E':
	if (!set_env_action(optarg))
	  usage();
	break;
      case 'f':
	filter_syscalls++;
	break;
      case 'k':
	stack_limit = atol(optarg);
	break;
      case 'i':
	redir_stdin = optarg;
	break;
      case 'm':
	memory_limit = atol(optarg);
	break;
      case 'M':
	meta_open(optarg);
	break;
      case 'o':
	redir_stdout = optarg;
	break;
      case 'p':
	if (!set_path_action(optarg))
	  usage();
	break;
      case 'r':
	redir_stderr = optarg;
	break;
      case 's':
	if (!set_syscall_action(optarg))
	  usage();
	break;
      case 't':
	timeout = 1000*atof(optarg);
	break;
      case 'T':
	syscall_action[__NR_times] = A_YES;
	break;
      case 'v':
	verbose++;
	break;
      case 'w':
        wall_timeout = 1000*atof(optarg);
	break;
      case 'x':
	extra_timeout = 1000*atof(optarg);
      case 'A':
  prog_argv[prog_argc++] = strdup(optarg);
  break;
	break;
      default:
	usage();
      }
  if (optind >= argc)
    usage();

  sanity_check();
  uid = geteuid();
  if (setreuid(uid, uid) < 0)
    die("setreuid: %m");
  box_pid = fork();
  if (box_pid < 0)
    die("fork: %m");
  if (!box_pid) {
    int real_argc = prog_argc + argc - optind;
    char **real_argv = xmalloc(sizeof(char*) * (real_argc));
    for (int i = 0;i < argc-optind;i++)
      real_argv[i] = strdup(argv[i+optind]);
    for (int i = 0;i < prog_argc;i++)
      real_argv[argc - optind + i] = strdup(prog_argv[i]);
    box_inside(real_argc, real_argv);
  } else
    boxkeeper();
  die("Internal error: fell over edge of the world");
}
