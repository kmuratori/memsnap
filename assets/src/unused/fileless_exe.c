#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include "lab_common.h"

int run_fileless(const char *source_binary) {
    int fd;
    char fd_path[64];
    struct stat st;
    unsigned char *buf;
    size_t size;
    FILE *src;

    printf("[*] Fileless Execution (memfd_create) - Source: %s\n", source_binary);

    src = fopen(source_binary, "rb");
    if (!src) {
        perror("[-] fopen source failed");
        return -1;
    }
    fstat(fileno(src), &st);
    size = st.st_size;
    buf = malloc(size);
    if (!buf) {
        fclose(src);
        return -1;
    }
    fread(buf, 1, size, src);
    fclose(src);

    fd = syscall(SYS_memfd_create, "memfd", 0);
    if (fd == -1) {
        perror("[-] memfd_create failed");
        free(buf);
        return -1;
    }
    write(fd, buf, size);
    free(buf);

    snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
    printf("[+] Executing from %s\n", fd_path);

    pid_t child = fork();
    if (child == 0) {
        char *envp[] = { NULL };
        execve(fd_path, (char *[]){ fd_path, NULL }, envp);
        perror("[-] execve fileless failed");
        _exit(1);
    }
    printf("[+] Fileless process running, PID: %d\n", child);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }
    return run_fileless(argv[1]);
}
