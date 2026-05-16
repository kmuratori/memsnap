/*
 * team_tnt_sim.c — TeamTNT Cloud Cryptominer Simulation
 *
 * Memory dump indicators:
 *  - XMRig worker thread strings in heap (pool address, wallet)
 *  - AWS credential strings (AKIA prefix) in process environment / heap
 *  - Docker socket path strings
 *  - Base64-encoded shell scripts in heap
 *  - IRC C2 strings in network buffers
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "lab_common.h"

/* ── XMRig pool strings (visible in memory dump) ── */
static const char *xmrig_pools[] = {
    "stratum+tcp://pool.supportxmr.com:3333",
    "stratum+tcp://xmrpool.eu:5555",
    "stratum+tcp://mine.c3pool.com:13333",
    NULL
};

/* ── Fake AWS credentials (AKIA prefix) ── */
static const char *aws_creds[] = {
    "AKIAIOSFODNN7EXAMPLE",
    "AKIAWJKL3XYZEXAMPLE2",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "AKIA_FAKE_SECRET_KEY",
    NULL
};

/* ── Docker socket path ── */
static const char *docker_socket = "unix:///var/run/docker.sock";

/* ── Base64-encoded shell script ── */
static const char *b64_script =
    "IyEvYmluL2Jhc2gKZG9ja2VyIHB1bGwgbml0cm9tYWx0ZS94bXJpZwpleHBvcnQg"
    "VE9QX1BPT0w9c3RyYXR1bSt0Y3A6Ly9wb29sLm1pbmV4bXIuY29tOjQ0NDQK";

/* ── IRC C2 ── */
static const char *irc_c2 = "irc.teamtnt.anondns.net:6667";

static int keep_running = 1;
// static void handler(int sig) { keep_running = 0; }
static void handler() { keep_running = 0; }

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;

    if (fork() != 0) exit(0);
    setsid();
    if (fork() != 0) exit(0);

    prctl(PR_SET_NAME, "[docker-cpu]", 0, 0, 0);
    signal(SIGTERM, handler);
    signal(SIGINT,  handler);

    /* ── 1. XMRig pool strings in heap ── */
    char **pool_strings = malloc(sizeof(char *) * 8);
    for (int i = 0; xmrig_pools[i]; i++) {
        pool_strings[i] = strdup(xmrig_pools[i]);
    }
    /* Add wallet address */
    char *wallet = strdup("48edfHu7V9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y9Z2Y");

    /* ── 2. AWS credentials in process environment ── */
    setenv("AWS_ACCESS_KEY_ID", aws_creds[0], 1);
    setenv("AWS_SECRET_ACCESS_KEY", aws_creds[2], 1);
    setenv("AWS_DEFAULT_REGION", "us-east-1", 1);
    /* Also put in heap for memory dump visibility */
    char **heap_creds = malloc(sizeof(char *) * 8);
    for (int i = 0; aws_creds[i]; i++) {
        heap_creds[i] = strdup(aws_creds[i]);
    }

    /* ── 3. Docker socket path in heap ── */
    char *docker_path = strdup(docker_socket);

    /* ── 4. Base64 script in heap ── */
    char *b64_heap = strdup(b64_script);

    /* ── 5. IRC C2 strings in anon mapping (simulates network buffer) ── */
    void *net_buf = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (net_buf != MAP_FAILED) {
        memcpy(net_buf, irc_c2, strlen(irc_c2) + 1);
        memcpy((char *)net_buf + 256, "USER tnt_bot 0 * :realname", 25);
        memcpy((char *)net_buf + 512, "NICK tnt_bot_1337", 17);
    }

    /* ── 6. Simulate Docker API access marker ── */
    FILE *docker_marker = fopen("/tmp/.teamtnt_docker", "w");
    if (docker_marker) {
        fprintf(docker_marker,
                "TEAMTNT_DOCKER_API_ACCESS: scanning for open APIs\n");
        fprintf(docker_marker, "container_name=redis_malicious\n");
        fprintf(docker_marker, "images_pulled=xmrig_monero_latest\n");
        fclose(docker_marker);
    }

    log_attack("team_tnt", "TeamTNT cloud cryptominer simulation active");

    /* ── 7. Main loop — simulate mining + lateral movement ── */
    while (keep_running) {
        /* Simulate CPU work (miner hash rate) */
        volatile unsigned long x = 0;
        for (int i = 0; i < 1000000; i++) x += i * 0xdeadbeef;

        /* Simulate lateral movement: check for SSH keys */
        FILE *ssh_check = fopen("/root/.ssh/authorized_keys", "r");
        if (ssh_check) {
            /* Would exfiltrate — memory dump shows this pattern */
            fclose(ssh_check);
        }

        sleep(2);
    }

    /* Cleanup */
    for (int i = 0; xmrig_pools[i]; i++) free(pool_strings[i]);
    free(pool_strings);
    free(wallet);
    for (int i = 0; aws_creds[i]; i++) free(heap_creds[i]);
    free(heap_creds);
    free(docker_path);
    free(b64_heap);
    if (net_buf != MAP_FAILED) munmap(net_buf, 4096);
    return 0;
}
