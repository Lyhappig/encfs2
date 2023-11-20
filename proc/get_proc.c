#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>

/**
gcc get_proc.c -Wall -o get_proc
*/

void split_name(char *line, char *name) {
	int i = 5;
	while(line[i] == ' ' || line[i] == '\t' || line[i] == '\n') {
		i++;
	}
	for(int j = i; j < strlen(line); j++) {
		if(line[j] != '\n')
			name[j - i] = line[j];
	}
}


void get_pname(char *name, char *pid, FILE *fw) {
	char fname[64];
	char line[256];
    sprintf(fname, "/proc/%s/status", pid);
    fprintf(fw, "%s ", fname);
	FILE *fp = fopen(fname, "r");
	fgets(line, 256, fp);
	split_name(line, name);
	fclose(fp);
}

int is_number(char *s) {
    for(int i = 0; i < strlen(s); i++) {
        if(s[i] < '0' || s[i] > '9') 
            return 0;
    }
    return 1;
}

int main() {
    DIR *dir;
    struct dirent *ent;
    char *path = "/proc"; // 目录路径
    if ((dir = opendir(path)) != NULL) {
        // 成功打开目录
        // ...
    } else {
        // 打开目录失败
        perror("无法打开目录");
        return 1;
    }
    char fname[4096];
    FILE *fp = fopen("AllProcess", "w");
    while ((ent = readdir(dir)) != NULL) {
        if(is_number(ent->d_name)) {
            memset(fname, 0, sizeof(fname));
            get_pname(fname, ent->d_name, fp);
            fprintf(fp, "%s\n", fname);
        }
    }
    closedir(dir);
    return 0;
}