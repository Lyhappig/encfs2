#include "access-control.h"


void split(char *path, char *user, char *src, char c) {
    if(src == NULL || strlen(src) == 0) return;
    int pos = -1;
    int i;
    int len = (int) strlen(src);
    for(i = 0; i < len; i++) {
        if(src[i] == c) {
            pos = i;
            break;
        }
    }
    if(pos < 0) {
        perror("can't find split string by space\n");
        exit(EXIT_FAILURE);
    }
    for(i = 0; i < pos; i++) {
        path[i] = src[i];
    }
    path[pos] = '\0';
    for(i = pos + 1; i < len; i++) {
        user[i - pos - 1] = src[i];
    }
    user[len - pos - 1] = '\0';
}

char *get_user() {
    struct passwd* pwd;
	pwd = getpwuid(get_encfs_uid());
    return pwd->pw_name;
}

/**
 * 检查用户是否合法（出现在白名单）
 * @return 出现在白名单则返回1；否则视为黑名单返回0
*/
int check_user_open_access(char *fpath) {
    char *cur_user = (char *) malloc(MAX_USER_LEN * sizeof(char));
    cur_user = get_user();

    log_msg("       int function check_user_open_access\n");
    log_msg("current path: %s\ncurrent user: %s\n", fpath, cur_user);

	FILE *user_white_list = fopen(USER_WHITE_LIST, "r");

    char *line;
    char *path;
    char *user;
	int len;
	int ok = 0;

    if(strcmp(cur_user, "root") == 0) return 1;

	if (user_white_list == NULL) {
        log_msg("can't read user_white_list\n");
        return 0;
    }

    line = (char *) malloc((PATH_MAX + MAX_USER_LEN + 1) * sizeof(char));
    path = (char *) malloc(PATH_MAX * sizeof(char));
    user = (char *) malloc(MAX_USER_LEN * sizeof(char));
    

    while(fgets(line, PATH_MAX + MAX_USER_LEN + 1, user_white_list) != NULL) {
		len = strlen(line);
        if(line[len - 1] == '\n') {
			line[len - 1] = '\0';
		}
        split(path, user, line, ' ');
        if(strcmp(path, fpath) == 0 && strcmp(user, get_user()) == 0) {
			ok = 1;
			break;
		}
    }

    free(line);
	free(path);
    free(user);
    fclose(user_white_list);
	return ok;
}