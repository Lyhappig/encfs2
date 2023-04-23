#ifndef ACCESS_CONTROL_H
#define ACCESS_CONTROL_H

#include <stdio.h>
#include <pwd.h>
#include <linux/limits.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define MAX_USER_LEN 32
#define USER_WHITE_LIST "/home/fuse_code/code/encfuse/.secret/user"
#define PROCESS_WHITE_LIST "/home/fuse_code/code/encfuse/.secret/precess"

typedef unsigned int uid_t;

extern void log_msg(const char *, ...);

extern uint32_t get_encfs_uid();

char *get_user();

int check_user_open_access(char *);

char *get_process();

int check_process_access(char *);

#endif  //ACCESS_CONTROL_H