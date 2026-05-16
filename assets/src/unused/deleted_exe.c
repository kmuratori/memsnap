#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "lab_common.h"

int run_deleted_exe(const char *binary_path) {
    struct stat st;
    if (stat(binary_path, &st) != 0) {
        printf("[-] Binary not found: %s\n", binary_path);
        return -1;
    }

    printf("[*] Deleted Executable - Binary: %s\n", binary_path);

    pid_t child = fork();
    if (child == -1) {
        perror("[-] fork failed");
        return -1;
    }
    if (child == 0) {
        execl(binary_path, binary_path, NULL);
        perror("[-] exec failed in child");
        _exit(1);
    }

    usleep(500000);
    if (unlink(binary_path) == 0) {
        printf("[+] Binary deleted from disk: %s\n", binary_path);
        printf("[!] /proc/%d/exe now shows '(deleted)'\n", child);
    } else {
        perror("[-] Failed to delete binary");
    }
    printf("[+] Child PID: %d still running\n", child);
    set_flag("/tmp/.deleted_exe_active");
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    return run_deleted_exe(argv[1]);
}
