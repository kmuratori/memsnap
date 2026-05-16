/*
 * cred_scrape_v2.c — credential scraper simulation
 *
 * Forensic artifacts produced:
 *   - SSH private key headers in heap  → vmaregexscan "BEGIN.*PRIVATE KEY"
 *   - Shadow hash format strings       → vmaregexscan "\$6\$"
 *   - /etc/shadow path reference       → vmaregexscan "etc/shadow"
 *   - /root/.ssh path reference        → vmaregexscan "\.ssh"
 *   - Large resident heap buffer       → malfind anomaly (size)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <time.h>

/* Synthetic shadow-format entries (user:$id$salt$hash:...) */
static const char *SYNTHETIC_SHADOW[] = {
    "root:$6$rounds=5000$rAnDoMsAlT1234$"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "CCCCCCCCCC.:19800:0:99999:7:::",
    "admin:$6$rounds=5000$xYzAbC987654$"
        "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD"
        "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        "FFFFFFFFFF.:19801:0:99999:7:::",
    "ubuntu:$y$j9T$fAkEsAlTsTrInG$"
        "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG.:19802::",
    "daemon:!:19000:0:99999:7:::",
    "nobody:*:18000:0:99999:7:::",
    NULL
};

/* Synthetic SSH private key material */
static const char *SYNTHETIC_SSH_KEYS[] = {
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29E3wPzM/M0A==\n"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\n"
    "-----END RSA PRIVATE KEY-----\n",

    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\n"
    "-----END OPENSSH PRIVATE KEY-----\n",

    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHQCAQEEIFakECuRvEcPrivateKeyMaterialHereAAAAAAAAAAAAAAAAAAAAAAAA\n"
    "-----END EC PRIVATE KEY-----\n",

    NULL
};

/* Path references that a real scraper would access */
static const char *PATH_REFERENCES[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/root/.ssh/id_rsa",
    "/root/.ssh/id_ed25519",
    "/home/ubuntu/.ssh/id_rsa",
    "/home/ubuntu/.ssh/authorized_keys",
    "/var/backups/shadow.bak",
    NULL
};

/* Staging buffer marker */
#define STAGING_MARKER  "CREDSCRAPE_STAGING_BUFFER_v2"
#define STAGING_SIZE    (2 * 1024 * 1024)  /* 2 MB — large enough for malfind */
#define PID_FILE        "/tmp/cred_scrape.pid"
#define FLAG_FILE       "/tmp/.cred_scrape_active"

static volatile int keep_running = 1;

static void handle_signal(int sig) {
    (void)sig;
    keep_running = 0;
}

static void write_pid(void) {
    FILE *f = fopen(PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
    f = fopen(FLAG_FILE, "w");
    if (f) fclose(f);
}

static void cleanup_pid(void) {
    unlink(PID_FILE);
    unlink(FLAG_FILE);
}

static char *build_staging_buffer(void) {
    char *buf = (char *)malloc(STAGING_SIZE);
    if (!buf) {
        perror("malloc");
        return NULL;
    }
    memset(buf, 0, STAGING_SIZE);

    size_t off = 0;
    size_t remaining;

    /* Header marker */
    remaining = STAGING_SIZE - off;
    off += snprintf(buf + off, remaining,
        "%s\n"
        "=== simulated credential harvest ===\n"
        "target: /etc/shadow\n"
        "target: /root/.ssh/\n\n",
        STAGING_MARKER);

    /* Path references */
    for (int i = 0; PATH_REFERENCES[i]; i++) {
        remaining = STAGING_SIZE - off;
        if (remaining < 256) break;
        off += snprintf(buf + off, remaining,
            "[access] %s\n", PATH_REFERENCES[i]);
    }

    /* Shadow entries */
    off += snprintf(buf + off, STAGING_SIZE - off, "\n[/etc/shadow contents]\n");
    for (int i = 0; SYNTHETIC_SHADOW[i]; i++) {
        remaining = STAGING_SIZE - off;
        if (remaining < 512) break;
        off += snprintf(buf + off, remaining, "%s\n", SYNTHETIC_SHADOW[i]);
    }

    /* SSH keys */
    off += snprintf(buf + off, STAGING_SIZE - off, "\n[ssh private keys]\n");
    for (int i = 0; SYNTHETIC_SSH_KEYS[i]; i++) {
        remaining = STAGING_SIZE - off;
        if (remaining < 1024) break;
        off += snprintf(buf + off, remaining, "%s\n", SYNTHETIC_SSH_KEYS[i]);
    }

    off += snprintf(buf + off, STAGING_SIZE - off,
        "\n[staging complete] harvested credentials queued for exfiltration\n");

    return buf;
}

int main(void) {
    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    write_pid();
    atexit(cleanup_pid);

    fprintf(stderr, "[cred_scrape_v2] PID %d — building staging buffer...\n",
            getpid());

    char *staging = build_staging_buffer();
    if (!staging) {
        return 1;
    }

    fprintf(stderr, "[cred_scrape_v2] staging buffer at %p (%d MB) — resident, waiting\n",
            (void *)staging, (int)(STAGING_SIZE / (1024*1024)));

    struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
    while (keep_running) {
        nanosleep(&ts, NULL);
    }

    free(staging);
    return 0;
}
