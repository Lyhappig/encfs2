#ifndef ACCESS_H_
#define ACCESS_H_

#include <pwd.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <linux/limits.h>

#define MAX_USER_LEN 32
#define USER_WHITE_LIST "/.secret/user"
#define PROCESS_WHITE_LIST "/.secret/process"

char proc_dir[PATH_MAX];

char user_dir[PATH_MAX];

extern void log_msg(const char *, ...);

extern uid_t get_uid();

extern pid_t get_pid();

char *get_user();

int check_user_access(const char *);

char *get_process();

int check_proc_access(const char *);

#endif // ACCESS_H_