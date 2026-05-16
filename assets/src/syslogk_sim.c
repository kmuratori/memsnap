/*
 * syslogk_sim.c — Syslogk Netfilter Hooking Rootkit Simulation
 *
 * Memory dump indicators:
 *  - Netfilter hook presence (simulated via fake nf_hook table)
 *  - Magic string pattern in packet inspection
 *  - Hidden process loaded from tmpfs
 *  - Module present in raw memory but absent from lsmod
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
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include "lab_common.h"

/* Magic HTTP header that triggers payload execution */
static const char *magic_header = "X-Syslogk-Trigger: activate";
static const char *magic_header_short = "X-Syslogk";

/* Netfilter hook simulation - fake hook table in memory */
typedef struct {
    int     hooknum;       /* NF_INET_PRE_ROUTING = 0 */
    int     pf;            /* NFPROTO_IPV4 = 2 */
    int     priority;      /* NF_IP_PRI_FIRST = INT_MAX */
    void    *hook_fn;      /* Address of hook function */
    char    name[32];      /* Hook name in memory */
} nf_hook_entry_t;

static int keep_running = 1;
// static void handler(int sig) { keep_running = 0; }
static void handler() { keep_running = 0; }

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    prctl(PR_SET_NAME, "[syslogkd]", 0, 0, 0);
    signal(SIGTERM, handler);
    signal(SIGINT, handler);

    /* ── 1. Netfilter hook table in memory ──
     *     Memory dump sees: a struct array mimicking nf_hook_ops
     *     with NF_INET_PRE_ROUTING hooknum and hook address pointer
     */
    nf_hook_entry_t *hook_table = mmap(NULL, 4096,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS,
                                       -1, 0);
    if (hook_table != MAP_FAILED) {
        hook_table[0].hooknum  = 0;    /* NF_INET_PRE_ROUTING */
        hook_table[0].pf       = 2;    /* NFPROTO_IPV4 */
        hook_table[0].priority = __INT_MAX__; /* NF_IP_PRI_FIRST */
        hook_table[0].hook_fn  = (void *)0xffffffffa0001000ULL; /* kernel addr */
        strncpy(hook_table[0].name, "syslogk_nf_pre_routing", 23);

        /* Also place a second hook for LOCAL_IN */
        hook_table[1].hooknum  = 1;    /* NF_INET_LOCAL_IN */
        hook_table[1].pf       = 2;
        hook_table[1].priority = __INT_MAX__;
        hook_table[1].hook_fn  = (void *)0xffffffffa0001200ULL;
        strncpy(hook_table[1].name, "syslogk_nf_local_in", 20);
    }

    /* ── 2. Magic string pattern in packet inspection code ──
     *     Visible in memory dump alongside netfilter structures
     */
    void *inspect_code = mmap(NULL, 4096,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (inspect_code != MAP_FAILED) {
        /* Plant the magic header string (used to trigger payload) */
        memcpy(inspect_code, magic_header, strlen(magic_header) + 1);
        /* Also plant the shorter trigger pattern */
        memcpy((char *)inspect_code + 256, magic_header_short,
               strlen(magic_header_short) + 1);
        /* Add a "packet rule" structure */
        memcpy((char *)inspect_code + 512,
               "MAGIC_HTTP_HEADER_TRIGGER=syslogk_activate", 42);
    }

    /* ── 3. Hidden tmpfs process simulation ──
     *     Creates a child that appears to run from tmpfs
     */
    pid_t child = fork();
    if (child == 0) {
        /* Child masquerades as a tmpfs-loaded process */
        prctl(PR_SET_NAME, "[kworker]", 0, 0, 0);
        /* Create /proc/X/exe pointing to tmpfs-like location */
        char exe_link[64];
        snprintf(exe_link, sizeof(exe_link), "/proc/%d/exe", getpid());
        /* Simulate by writing a marker */
        FILE *f = fopen("/tmp/.syslogk_payload", "w");
        if (f) {
            fprintf(f, "pid=%d payload_from_tmpfs\n", getpid());
            fclose(f);
        }
        pause();
        _exit(0);
    }
    FILE *pidfile = fopen("/tmp/syslogk_child.pid", "w");
    if (pidfile) { fprintf(pidfile, "%d", child); fclose(pidfile); }

    /* ── 4. /sys/module vs /proc/modules discrepancy marker ── */
    FILE *marker = fopen("/tmp/.syslogk_module_hidden", "w");
    if (marker) {
        fprintf(marker,
                "syslogk.ko: present in raw memory, hidden from lsmod\n"
                "netfilter hooks: NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN\n"
                "hook_addrs: 0xffffffffa0001000, 0xffffffffa0001200\n");
        fclose(marker);
    }

    log_attack("syslogk", "Syslogk netfilter hook rootkit simulation active");

    /* ── 5. Main loop — listen for "magic" packets ── */
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock >= 0) {
        while (keep_running) {
            char buf[65536];
            struct sockaddr_in src;
            socklen_t srclen = sizeof(src);
            int n = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
                            (struct sockaddr *)&src, &srclen);
            (void)n;
            sleep(1);
        }
        close(sock);
    } else {
        while (keep_running) sleep(10);
    }

    /* Cleanup child */
    if (child > 0) kill(child, SIGTERM);
    if (hook_table != MAP_FAILED) munmap(hook_table, 4096);
    if (inspect_code != MAP_FAILED) munmap(inspect_code, 4096);
    return 0;
}
