/*
 * skidmap_sim.c — Skidmap Multi-component malware simulation
 *
 * Memory dump indicators:
 *  - Counterfeit kmod with spoofed kernel version string in module memory
 *  - XMRig signature strings in heap (stratum+tcp://pool)
 *  - PAM module .so mapped in sshd/sudo process
 *  - Hook of /proc/net/dev to zero out counters
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <time.h>
#include "lab_common.h"

/* XMRig-like strings — will appear in memory dumps */
static const char *xmr_pools[] = {
    "stratum+tcp://pool.minexmr.com:4444",
    "stratum+tcp://xmrpool.eu:3333",
    "stratum+tcp://monero.hashvault.pro:5555",
    NULL
};

/* Fake wallet address (testnet, not real) */
static const char *wallet = "48edfHu7V9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y";

/* Spoofed kernel version string — looks like a real kernel module */
static const char *fake_kmod_version = "skd_crypto v2.1.3 (6.18.12+kali-amd64)";

/* PAM backdoor name */
static const char *pam_module_name = "pam_skidmap.so";

static int keep_running = 1;
// static void handler(int sig) { keep_running = 0; }
static void handler() { keep_running = 0; }

void simulate_cpu_mining(void) {
    /* Busy-wait to simulate mining CPU load */
    volatile unsigned long long x = 0;
    for (int i = 0; i < 50000000; i++) {
        x += (i * 0xdeadbeef) ^ (i >> 3);
    }
    (void)x;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    signal(SIGTERM, handler);
    signal(SIGINT, handler);

    prctl(PR_SET_NAME, "[skd_crypto]", 0, 0, 0);

    /* ── 1. Plant XMRig strings in heap (visible in memory dump) ── */
    char **heap_strings = malloc(sizeof(char*) * 10);
    for (int i = 0; xmr_pools[i]; i++) {
        heap_strings[i] = strdup(xmr_pools[i]);
    }
    char *wallet_copy = strdup(wallet);
    (void)wallet_copy;

    /* ── 2. Fake kmod memory: RWX page with spoofed version ── */
    void *kmod_page = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (kmod_page != MAP_FAILED) {
        memcpy(kmod_page, fake_kmod_version, strlen(fake_kmod_version) + 1);
        /* Add ELF-ish header to look like a kernel module */
        memcpy(kmod_page, "\x7f" "ELF", 4);
    }

    /* ── 3. Simulate PAM module presence via /tmp marker ── */
    char pam_path[256];
    snprintf(pam_path, sizeof(pam_path), "/tmp/.%s", pam_module_name);
    FILE *fp = fopen(pam_path, "w");
    if (fp) { fprintf(fp, "pam_skidmap.so v1.0 loaded\n"); fclose(fp); }

    /* ── 4. Simulate /proc/net/dev counter zeroing ──
     *     We create a fake entry that masks network activity
     */
    FILE *netdev = fopen("/tmp/.skidmap_netdev_backup", "w");
    if (netdev) {
        fprintf(netdev, "skidmap: hooked /proc/net/dev counters zeroed\n");
        fclose(netdev);
    }

    log_attack("skidmap", "Cryptominer + Fake KMOD + PAM backdoor active");

    /* ── 5. Main loop — simulate mining bursts ── */
    while (keep_running) {
        simulate_cpu_mining();
        sleep(1);
    }

    free(heap_strings);
    free(wallet_copy);
    if (kmod_page != MAP_FAILED) munmap(kmod_page, 4096);
    return 0;
}
