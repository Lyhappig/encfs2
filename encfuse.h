#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <linux/limits.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>

#include "access-control.h"
#include "file-crypt.h"

// log打印控制
#define CHECK_ENC_LOG 1
#define CHECK_KEY_LOG 1
#define ENC_LOG 1
#define READ_DIR_LOG 0
#define MKDIR_LOG 1
#define OPEN_LOG 1
#define READ_LOG 1
#define WRITE_LOG 1
#define CREATE_LOG 1
#define ATTR_LOG 0
#define ACCESS_LOG 0
#define READ_LINK_LOG 0
#define MKNOD_LOG 0
#define UNLINK_LOG 0
#define RM_DIR_LOG 0
#define SYMLINK_LOG 0
#define RENAME_LOG 0
#define LINK_LOG 0
#define CHMOD_LOG 0
#define CHOWN_LOG 0
#define TRUNCATE_LOG 0
#define UTIMENS_LOG 0
#define STATFS_LOG 0

#define MAX_SIZE 131072
#define ENCRYPT 	1
#define DECRYPT 	0
#define COPY 		-1
#define XATRR_ENCRYPTED_FLAG "user.enfuse.encrypted"
#define XATTR_FILE_PASSPHRASE "user.enfuse.passphrase"
#define USAGE "Usage:\n\t./enfuse <Mount Point> <Mirror Directory> <Passkey>\n"

#define ENCFS_DATA ((struct encfs_state *) fuse_get_context()->private_data)
#define ENCFS_UID ((int) fuse_get_context()->uid)


struct encfs_state {
	char *mirror_dir;
	char *passkey;
	FILE *logfile;
};

FILE *log_open();
void log_msg(const char *, ...);
uint32_t get_encfs_uid();
