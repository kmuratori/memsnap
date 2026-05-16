/*
 * reptile_sim.c — Reptile LKM Rootkit Simulation
 *
 * Memory dump indicators:
 *  - Hooked VFS function pointers (vfs_read, vfs_write) in kernel memory
 *  - Kernel module not in /sys/module but in raw memory
 *  - Magic packet listener on raw socket
 *  - Backdoor shell code in BSS segment
 *
 * NOTE: This is a user-space simulation that creates the same forensic
 * fingerprints WITHOUT loading a real kernel module.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include "lab_common.h"

/* Reptile magic port-knocking sequence */
static const int knock_ports[] = { 12345, 23456, 34567, 45678 };
#define KNOCK_COUNT 4

static int keep_running = 1;
// static void handler(int sig) { keep_running = 0; }
static void handler() { keep_running = 0; }

/* Simulated VFS hook — a function pointer stored in "kernel-like" memory */
typedef ssize_t (*vfs_read_t)(void *, void *, size_t, void *);
typedef ssize_t (*vfs_write_t)(void *, const void *, size_t, void *);

/* Fake "hooked" function pointers stored in RWX page */
static vfs_read_t hooked_vfs_read = NULL;
static vfs_write_t hooked_vfs_write = NULL;

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    prctl(PR_SET_NAME, "[reptiled]", 0, 0, 0);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);

    /* ── 1. Create RWX page with "VFS hook" function pointers ──
     *     Memory dump sees: anonymous RWX page with function pointer tables
     */
    void *vfs_hook_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (vfs_hook_page != MAP_FAILED) {
        /* Place "hooked" function pointers at known offsets */
        memset(vfs_hook_page, 0x41, 4096);  /* Fill with marker */
        /* Store pointers as if they were vfs_read / vfs_write hooks */
        hooked_vfs_read  = (vfs_read_t)((char *)vfs_hook_page + 128);
        hooked_vfs_write = (vfs_write_t)((char *)vfs_hook_page + 256);
        /* Plant Reptile magic string */
        memcpy(vfs_hook_page, "REPTILE_VFS_HOOK_ACTIVE", 23);
    }

    /* ── 2. Create raw socket for "port knocking" backdoor ──
     *     Visible in /proc/<pid>/fd/ as socket:[inode] with no ss entry
     */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock >= 0) {
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        /* This socket will appear in memory dumps */
        char *sock_buf = malloc(65536);
        memset(sock_buf, 0, 65536);
        /* Store knock ports in heap next to socket buffer */
        memcpy(sock_buf+1024, knock_ports, sizeof(knock_ports));
        (void)sock_buf;
    }

    /* ── 3. Plant "kernel module" markers in /proc/misc-style ──
     *     Simulates a module hidden from lsmod but visible in /dev/mem
     */
    FILE *mod_marker = fopen("/tmp/.reptile_kmod", "w");
    if (mod_marker) {
        fprintf(mod_marker, "reptile: hidden LKM v2.0.1\n");
        fprintf(mod_marker, "hooked: vfs_read=%p vfs_write=%p\n",
                (void *)hooked_vfs_read, (void *)hooked_vfs_write);
        fclose(mod_marker);
    }

    /* ── 4. Backdoor shell code segment simulation ──
     *     Memory dump sees shellcode in BSS-like anonymous region
     */
    void *bss_seg = mmap(NULL, 8192, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (bss_seg != MAP_FAILED) {
        /* Place NOP-sled + shell signature */
        memset(bss_seg, 0x90, 4096);  /* NOP sled */
        memcpy((char *)bss_seg + 4096 - 32,
               "[REPTILE_bindshell_ready]", 26);
    }

    log_attack("reptile", "Reptile VFS hook rootkit simulation active");

    while (keep_running) {
        /* Simulate port-knocking listener activity */
        if (sock >= 0) {
            char pkt[65536];
            struct sockaddr_in src;
            socklen_t srclen = sizeof(src);
            int n = recvfrom(sock, pkt, sizeof(pkt), MSG_DONTWAIT,
                            (struct sockaddr *)&src, &srclen);
            if (n > 0) {
                log_attack("reptile", "Port-knocking backdoor: packet received");
            }
        }
        sleep(1);
    }

    if (vfs_hook_page != MAP_FAILED) munmap(vfs_hook_page, 4096);
    if (bss_seg != MAP_FAILED) munmap(bss_seg, 8192);
    return 0;
}
