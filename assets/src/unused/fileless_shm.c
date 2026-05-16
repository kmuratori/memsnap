#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "lab_common.h"

int run_fileless_shm(const char *binary_path) {
    printf("[*] Fileless execution via shared memory (tmpfs)\n");
    
    int shm_fd = shm_open("/xSHM_PAYLOAD", O_CREAT | O_RDWR, 0755);
    if (shm_fd == -1) { perror("[-] shm_open failed"); return -1; }
    
    FILE *src = fopen(binary_path, "rb");
    if (!src) { perror("[-] fopen failed"); return -1; }
    
    struct stat st;
    fstat(fileno(src), &st);
    ftruncate(shm_fd, st.st_size);
    
    void *map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_SHARED, shm_fd, 0);
    if (map == MAP_FAILED) { perror("[-] mmap failed"); return -1; }
    
    fread(map, 1, st.st_size, src);
    fclose(src);
    
    printf("[+] Binary loaded into /dev/shm/xSHM_PAYLOAD\n");
    
    pid_t child = fork();
    if (child == 0) {
        execve("/dev/shm/xSHM_PAYLOAD", 
               (char *[]){ "/dev/shm/xSHM_PAYLOAD", NULL }, NULL);
        _exit(1);
    }
    
    printf("[+] Process running from shared memory, PID: %d\n", child);
    set_flag("/tmp/.fileless_shm_active");
    return 0;
}

int main(int argc, char *argv[]) {
    const char *path = argc > 1 ? argv[1] : "assets/build/pause_binary";
    return run_fileless_shm(path);
}
