/*
 * bpf_backdoor.c — BPFDoor Simulation
 * Passive backdoor using raw BPF socket filters.
 *
 * Memory dump indicators:
 *  - BPF program bytecode in process memory (rwx pages)
 *  - Raw socket file descriptors in fdinfo
 *  - Magic byte sequence (0x7255) as BPF filter constant operand
 *  - Process waiting on recvfrom with SO_ATTACH_FILTER sockopt
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <linux/filter.h>
#include <linux/if_packet.h>
#include <arpa/inet.h>
#include <net/if.h>

/* ── Magic packet signatures (visible in memory dump) ── */
#define MAGIC_UDP_WORD  0x7255    /* BPFDoor classic */
#define MAGIC_TCP_WORD  0x5293

static int keep_running = 1;
// static void sig_handler(int sig) { keep_running = 0; }
static void sig_handler() { keep_running = 0; }

int main(int argc, char *argv[]) {
    int sock;
    char buf[65536];
    struct sockaddr_ll saddr;
    socklen_t slen = sizeof(saddr);
    (void)argc; (void)argv;

    /* Daemonise */
    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    /* Masquerade as a kernel thread */
    prctl(PR_SET_NAME, "[kbpfd]", 0, 0, 0);

    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);

    /* ── 1. Create raw socket  ──
     *     => visible in /proc/<pid>/fd/ as socket:[inode]
     *     => no listening port → invisible to ss -lntp
     */
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) { perror("socket"); return 1; }

    /* ── 2. BPF filter bytecode (lives in process memory) ──
     *     Filter: accept only UDP on ephemeral ports
     */
    struct sock_filter bpf_code[] = {
        /* Ethernet type == IPv4 ? */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 5),
        /* IP protocol == UDP ? */
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 23),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 3),
        /* UDP dest port > 1024 ? */
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 36),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 1025, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, 0),                /* drop */
        BPF_STMT(BPF_RET | BPF_K, 0x0000ffff),       /* accept full pkt */
    };
    struct sock_fprog bpf_prog = {
        .len    = sizeof(bpf_code) / sizeof(bpf_code[0]),
        .filter = bpf_code,
    };

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
                   &bpf_prog, sizeof(bpf_prog)) < 0) {
        perror("setsockopt SO_ATTACH_FILTER");
        close(sock);
        return 1;
    }

    /* ── 3. Allocate an RWX page & plant BPF bytecode + magic strings ──
     *     => Memory-dump indicator: anonymous RWX VMA
     */
    void *rwx = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (rwx != MAP_FAILED) {
        memcpy(rwx, bpf_code, sizeof(bpf_code));
        /* Plant magic strings for memory scanners */
        uint16_t *m = (uint16_t *)((char *)rwx + 512);
        m[0] = MAGIC_UDP_WORD;
        m[1] = MAGIC_TCP_WORD;
        memcpy((char *)rwx + 1024, "\x44\x30\xCD\x9F\x5E\x14\x27\x66", 8);
    }

    /* ── 4. Listen loop — recvfrom with BPF active ──
     *     => /proc/<pid>/fdinfo/<fd> shows SO_ATTACH_FILTER
     */
    while (keep_running) {
        int n = recvfrom(sock, buf, sizeof(buf), 0,
                         (struct sockaddr *)&saddr, &slen);
        if (n < 0) { if (errno == EINTR) break; usleep(10000); continue; }

        // struct ethhdr *eth  = (struct ethhdr *)buf;
        struct iphdr  *ip   = (struct iphdr  *)(buf + 14);
        int iphlen          = ip->ihl * 4;

        if (ip->protocol == IPPROTO_UDP && n > 14 + iphlen + 8 + 4) {
            uint16_t *magic = (uint16_t *)(buf + 14 + iphlen + 8);
            if (*magic == MAGIC_UDP_WORD) {
                /* Trigger detected — in real BPFDoor this spawns shell */
                write(2, "[BPFdoor] magic packet triggered\n", 34);
            }
        }
        usleep(1000);
    }

    if (rwx != MAP_FAILED) munmap(rwx, 4096);
    close(sock);
    return 0;
}
