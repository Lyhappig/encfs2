#include "access.h"


void split(char *dest1, char *dest2, char *src, char c) {
    if (src == NULL || strlen(src) == 0) return;
    int pos = -1;
    int i;
    int len = (int)strlen(src);
    for (i = 0; i < len; i++) {
        if (src[i] == c) {
            pos = i;
            break;
        }
    }
    if (pos < 0) {
        perror("can't find split string by space\n");
        exit(EXIT_FAILURE);
    }
    for (i = 0; i < pos; i++) {
        dest1[i] = src[i];
    }
    dest1[pos] = '\0';
    for (i = pos + 1; i < len; i++) {
        dest2[i - pos - 1] = src[i];
    }
    dest2[len - pos - 1] = '\0';
}


void split_name(char *line, char *name) {
	int i = 5, j, len = strlen(line);
	while(line[i] == ' ' || line[i] == '\t' || line[i] == '\n') {
		i++;
	}
	for(j = i; j < len; j++) {
		if(line[j] != '\n')
			name[j - i] = line[j];
	}
}


char *get_user() {
    struct passwd *pwd;
    pwd = getpwuid(get_uid());
    return pwd->pw_name;
}


void get_pname(char *name, pid_t pid) {
	char fname[64];
	char line[256];
    sprintf(fname, "/proc/%u/status", pid);
	FILE *fp = fopen(fname, "r");
	fgets(line, 256, fp);
	split_name(line, name);
	fclose(fp);
}


int check_user_access(const char *relapath) {
	char *cur_user = get_user();

    log_msg("       int function check_user_access:\n");
    log_msg("current relative path: %s\n", relapath);
    log_msg("current user: %s\n", cur_user);

    // if (strcmp(cur_user, "root") == 0) return 1;

    int len;
    int ok = 0;
    char line[PATH_MAX + MAX_USER_LEN + 1];
    char path[PATH_MAX];
    char user[MAX_USER_LEN];

    FILE *fp = fopen(user_dir, "r");
    if (fp == NULL) {
        log_msg("can't read user_white_list\n");
        return 0;
    }

    while (fgets(line, PATH_MAX + MAX_USER_LEN + 1, fp) != NULL) {
        len = strlen(line);
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        split(path, user, line, ' ');
        if (strcmp(path, relapath) == 0 && strcmp(user, get_user()) == 0) {
            ok = 1;
            break;
        }
    }
    fclose(fp);
    return ok;
}


int check_proc_access(const char *relapath) {
    char pname[PATH_MAX] = {'\0'};
    get_pname(pname, get_pid());

    log_msg("       int function check_process_access:\n");
    log_msg("current relative path: %s\n", relapath);
    log_msg("current proc: %s\n", pname);

    int len;
    int ok = 0;
    char line[PATH_MAX * 2 + 1];
    char path[PATH_MAX];
    char proc[PATH_MAX];

	FILE *fp = fopen(proc_dir, "r");
	if (fp == NULL) {
        log_msg("can't read proc_white_list\n\n");
        return 0;
    }

    while (fgets(line, PATH_MAX * 2 + 1, fp) != NULL) {
        len = strlen(line);
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        split(path, proc, line, ' ');
        if (strcmp(path, relapath) == 0 && strcmp(proc, pname) == 0) {
            ok = 1;
            break;
        }
    }
    fclose(fp);
	return ok;
}
