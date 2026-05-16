#include <stdio.h>
#include <unistd.h>
__attribute__((constructor)) void evil_init() {
    FILE *fp = fopen("/tmp/owned", "w");
    fprintf(fp, "Injected!\n");
    fclose(fp);
}
