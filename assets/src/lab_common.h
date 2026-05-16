#ifndef LAB_COMMON_H
#define LAB_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

extern unsigned char shell_pause[];
extern int shell_pause_len;
extern unsigned char shell_binsh[];
extern int shell_binsh_len;
extern unsigned char shell_bind[];
extern int shell_bind_len;

void set_flag(const char *path);
void clear_flag(const char *path);
void log_attack(const char *module, const char *msg);

#endif
