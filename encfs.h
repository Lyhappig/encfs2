#ifndef ENCFUSE_H
#define ENCFUSE_H

#include <fuse.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stddef.h>
#include <sys/time.h>
#include <sys/types.h>
#include <linux/limits.h>

#include "crypt.h"
#include "access.h"

// log控制
// #define ATTR_LOG
// #define ACCESS_LOG
#define CHMOD_LOG
#define CHOWN_LOG
#define CREATE_LOG
#define FSYNC_LOG
// #define GETATTR_LOG
// #define GETXATTR_LOG
#define LINK_LOG
#define LISTXATTR_LOG
#define MKDIR_LOG
#define MKNOD_LOG
#define OPEN_LOG
// #define READ_DIR_LOG
#define READ_LOG
#define READ_LINK_LOG
#define RELEASE_LOG
#define REMOVEXATTR_LOG
#define RENAME_LOG
#define RM_DIR_LOG
#define SETXATTR_LOG
#define STATFS_LOG
#define SYMLINK_LOG
#define TRUNCATE_LOG
#define UNLINK_LOG
#define UTIMENS_LOG
#define WRITE_LOG

#define MAX_SIZE 131072
#define ENCRYPT 	1
#define DECRYPT 	0
#define COPY 		-1

// 是否开启访问控制
#define ACCESS_CONTROL 1

// #define XATTR_KEY "user.enfuse.key"
// #define XATTR_IV "user.enfuse.iv"
#define XATTR_ENCRYPTED_FLAG "user.enfuse.encrypted"

#define USAGE "Usage:\n\t./enfuse <Mount Point> <Mirror Directory> <Passkey>\n"

#define O_WRITE(flags) ((flags) & (O_RDWR | O_WRONLY))
#define O_READ(flags)  (((flags) & (O_RDWR | O_RDONLY)) | !O_WRITE(flags))

#define ENCFS_DATA ((struct encfs_state *) fuse_get_context()->private_data)

struct encfs_state {
	char *mirror_dir;
	char *passkey;
	FILE *logfile;
};

// void log_msg(const char *, ...);

#endif /* ENCFUSE_H */
