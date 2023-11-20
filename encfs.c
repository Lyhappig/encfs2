#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR
#define HAVE_UTIMENSAT
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#include <stdlib.h>
#endif

#include "encfs.h"

static FILE* log_open() {
    FILE *logfile = fopen("./log/encfs.log", "w");
    if (logfile == NULL) {
		perror("logfile open failed");
		exit(EXIT_FAILURE);
    }
    setvbuf(logfile, NULL, _IOLBF, 0);
	return logfile;
}


void log_msg(const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    vfprintf(ENCFS_DATA->logfile, format, ap);
}


uid_t get_uid() {
	return fuse_get_context()->uid;
}


pid_t get_pid() {
	return fuse_get_context()->pid;
}


static void get_xattr(char *file_path, char *xattr_key, char *xattr_val) {
	int vsize = getxattr(file_path, xattr_key, NULL, 0);
	getxattr(file_path, xattr_key, xattr_val, vsize);
}


static off_t get_file_size(char *file_path) {
	struct stat file_info;
    // 获取文件信息
    if (stat(file_path, &file_info) != 0) {
        log_msg("获取文件信息出错\n");
        return 1;
    }
   	return file_info.st_size;
}


/**
 * 获取文件的绝对路径
 * @param fpath 挂载根路径
 * @param path 当前文件相对路径
 * @return 得到当前文件的绝对路径(fpath)
*/
static void xmp_getfullpath(char *fpath, const char *path) {
    strcpy(fpath, ENCFS_DATA->mirror_dir);
    strncat(fpath, path, PATH_MAX); 
}


/**
 * 获取文件的属性信息：
 * file：显示文件名
 * size：显示文件大小(单位：字节)
 * blocks：文件使用的数据块总数
 * IO Block：IO块大小
 * regular file：文件类型（常规文件）
 * device：设备编号
 * inode：Inode号
 * links：链接数
 * access：文件的读、写和执行权限
 * uid、gid：文件所有权的用户编号 uid和用户组编号gid
 * access time：表示我们最后一次访问（仅仅是访问，没有改动）文件的时间
 * modify time：表示我们最后一次修改文件的时间
 * change time：表示我们最后一次对文件属性改变的时间，包括权限，大小，属性等等
 * @param path 文件路径
 * @param stbuf 文件状态信息存储地址
 * @return 0/other: 成功/出错
*/
static int xmp_getattr(const char *path, struct stat *stbuf) {
	int res = 0;
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef GETATTR_LOG
		log_msg("		in function xmp_getattr:\n");
		log_msg("getattr: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lstat(fpath, stbuf);
	if (res == -1){
		return -errno;
	}
	return 0;
}

/**
 * 查看文件是否具有某种权限（读，写，执行）
 * @param path 文件路径
 * @param mask 权限类型
 * @return 0/other: 成功/出错
*/
static int xmp_access(const char *path, int mask) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef ACCESS_LOG
		log_msg("		in function xmp_access:\n");
		log_msg("access: %s\n", fpath);
		log_msg("\n");
	#endif
	
	/**
	 * access(): 返回给定路径文件的权限是否符合mask
	 * 四种权限：（F_OK(文件是否存在），R_OK(是否可读），W_OK（是否可以写入）,X_OK(是否可以运行）
	*/
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}


/**
 * 读取软链接指向的文件本身的内容
 * @param path 文件路径
 * @param buf 读取内容
 * @param size 长度
 * @return 0/other: 成功/出错 
*/
static int xmp_readlink(const char *path, char *buf, size_t size) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef READ_LINK_LOG
		log_msg("		in function xmp_readlink:\n");
		log_msg("readlink: %s\n", fpath);
		log_msg("\n");
	#endif

	/**
	 * readlink(): 读取符号链接文件本身的内容，得到链接所指向的文件名。
	 * 成功返回读取链接文件的字节数，失败返回 -1
	*/
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


/**
 * 获取访问挂载路径下文件的路径
 * @param path 文件路径
 * @param buf 
 * @param filler 在readdir()过程中增加一个实体
 * @param offset 无效参数
 * @param fi 无效参数
 * @return 0/other: 成功/出错
*/
static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi) {
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef READ_DIR_LOG
		log_msg("		in function xmp_readdir:\n");
		log_msg("read dir: %s\n", fpath);
		log_msg("\n");
	#endif

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef MKNOD_LOG
		log_msg("		in function xmp_mknod:\n");
		log_msg("mknode: %s\n", fpath);
		log_msg("\n");
	#endif

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef MKDIR_LOG
		log_msg("		in function xmp_mkdir:\n");
		log_msg("mkdir: %s\n", fpath);
		log_msg("\n");
	#endif

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef UNLINK_LOG
		log_msg("		in function xmp_unlink:\n");
		log_msg("unlink: %s\n", fpath);
		log_msg("\n");
	#endif

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef RM_DIR_LOG
		log_msg("		in function xmp_rmdir:\n");
		log_msg("rmdir: %s\n", fpath);
		log_msg("\n");
	#endif

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to) {
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#ifdef SYMLINK_LOG
		log_msg("		in function xmp_symlink:\n");
		log_msg("symlink: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = symlink(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to) {
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#ifdef RENAME_LOG
		log_msg("		in function xmp_rename:\n");
		log_msg("rename: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = rename(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to) {
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#ifdef LINK_LOG
		log_msg("		in function xmp_link:\n");
		log_msg("link: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = link(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef CHMOD_LOG
		log_msg("		in function xmp_chmod:\n");
		log_msg("chmod: %s\n", fpath);
		log_msg("\n");
	#endif

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef CHOWN_LOG
		log_msg("		in function xmp_chown:\n");
		log_msg("chown: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef TRUNCATE_LOG
		log_msg("		in function xmp_truncate:\n");
		log_msg("truncate: %s\n", fpath);
		log_msg("\n");
	#endif

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2]) {
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef UTIMENS_LOG
		log_msg("		in function xmp_utimens:\n");
		log_msg("utimens: %s\n", fpath);
		log_msg("\n");
	#endif

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}
#endif


static int xmp_open(const char *path, struct fuse_file_info *fi) {
	int res;
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef OPEN_LOG
		log_msg("		in function xmp_open:\n");
		log_msg("open relative: %s\n", path);
		log_msg("open absolute: %s\n", fpath);
		log_msg("\n");
	#endif

	#if ACCESS_CONTROL
		if(!check_user_access(path)) {
			return -EPERM;
		}
		if(!check_proc_access(path)) {
			return -EPERM;
		}
	#endif

	res = open(fpath, fi->flags);
	if (res == -1) {
		log_msg("can't open file, error\n");
		return -errno;
	}
	close(res);
	return 0;
}


int get_decrypt_data(char *file_path, char *buf, size_t size, off_t offset, int action) {
	int res = 0;
	unsigned char xattr_val[16] = {0};
	get_xattr(file_path, XATTR_ENCRYPTED_FLAG, xattr_val);
	if(memcmp(xattr_val, "true", 4) != 0) {
		action = COPY;
		log_msg("No %s attribute is set\n", XATTR_ENCRYPTED_FLAG);
	} else {
		log_msg("This file need to decrypt\n");
	}
	if(action == COPY) return 0;

	uint8_t* key = (char *)malloc(16);
	uint8_t* iv = (char *)malloc(16);
	res = get_key_iv(ENCFS_DATA->passkey, file_path, offset, key, iv);
	if(res == FAILURE) {
		log_msg("get_key_iv failed\n");
		return 0;
	}

	char *in = (char *) malloc(size);
	res = buf_crypt(buf, size, in, key, iv, action);
	if(res == FAILURE) {
		log_msg("buf_crypt error, error code: %d\n", errno);
		return -errno;
	}
	memcpy(buf, in, size);
	free(in), free(key), free(iv);
	return 0;
}

/**
 * 读取文件
 * @param buf 最终的读取内容
 * @return 读取文件的大小
*/
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi) 
{
	if(!O_READ(fi->flags))
    	return -EACCES;

	int fd;
	int res;
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	(void)fi;

	#ifdef READ_LOG
		log_msg("		in function xmp_read:\n");
		log_msg("read: %s\n", fpath);
		log_msg("size: %zu, offset: %zu.\n", size, offset);
		log_msg("file size: %i\n", get_file_size(fpath));
		log_msg("\n");
	#endif

	fd = open(fpath, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	if(get_decrypt_data(fpath, buf, res, offset, DECRYPT) != 0) {
		return -errno;
	}
	return res;
}


int get_encrypt_data(char *file_path, const char *buf, size_t size, off_t offset, char *out, int action) {
	int res = 0;
	unsigned char xattr_val[16] = {0};
	get_xattr(file_path, XATTR_ENCRYPTED_FLAG, xattr_val);
	if(memcmp(xattr_val, "true", 4) != 0) {
		action = COPY;
		log_msg("No %s attribute is set\n", XATTR_ENCRYPTED_FLAG);
	} else {
		log_msg("This file need to encrypt\n");
	}

	if(action == COPY) {
		memcpy(out, buf, size);
		return 0;
	}

	uint8_t* key = (char *)malloc(16);
	uint8_t* iv = (char *)malloc(16);
	res = get_key_iv(ENCFS_DATA->passkey, file_path, offset, key, iv);
	if(res == FAILURE) {
		log_msg("get_key_iv failed\n");
		memcpy(out, buf, size);
		return 0;
	}

	res = buf_crypt(buf, size, out, key, iv, action);
	if(res == FAILURE) {
		log_msg("buf_crypt error, error code: %d\n", errno);
		return -errno;
	}
	free(key), free(iv);
	return 0;
}


static int xmp_write(const char *path, const char *buf, size_t size,
			off_t offset, struct fuse_file_info *fi) 
{	
	if(!O_WRITE(fi->flags)) {
    	return -EACCES;
  	}

	int fd;
	int res;
	char fpath[PATH_MAX];
	char *ebuf = (char *) malloc(size);
	xmp_getfullpath(fpath, path);

	(void) fi;

	#ifdef WRITE_LOG
		log_msg("		in function xmp_write:\n");
		log_msg("write: %s\n", fpath);
		log_msg("size: %i, offset: %i\n", size, offset);
		log_msg("file size: %i\n", get_file_size(fpath));
		log_msg("\n");
	#endif

	fd = open(fpath, O_WRONLY);
	if (fd == -1) 
		return -errno;

	if(get_encrypt_data(fpath, buf, size, offset, ebuf, ENCRYPT)) {
		return -errno;
	}

	res = pwrite(fd, ebuf, size, offset);
	if (res == -1)
		res = -errno;
	free(ebuf);
	close(fd);
	return res;
}


static int xmp_create(const char* path, mode_t mode, 
			struct fuse_file_info* fi) {
	int res;
	
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef CREATE_LOG
		log_msg("		in function xmp_create:\n");
		log_msg("create: %s\n", fpath);
	#endif
	
    res = creat(fpath, mode);
    if(res == -1) {
		return -errno;
	}

	char flag[5] = "true";
	if(setxattr(fpath, XATTR_ENCRYPTED_FLAG, flag, 5, 0)) {
    	log_msg("error setting xattr of file %s\n", fpath);
    	return -errno;
   	}
   	log_msg("Create: file xatrr [%s, %s] correctly set %s\n", XATTR_ENCRYPTED_FLAG, flag, fpath);
	log_msg("\n");
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef RELEASE_LOG
		log_msg("		in function xmp_release:\n");
		log_msg("release: %s\n", fpath);
		log_msg("\n");
	#endif
	return 0;
}


static int xmp_statfs(const char *path, struct statvfs *stbuf) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef STATFS_LOG
		log_msg("		in function xmp_statfs:\n");
		log_msg("statfs: %s\n", fpath);
		log_msg("\n");
	#endif

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_fsync(const char *path, int isdatasync, 
			struct fuse_file_info *fi) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef FSYNC_LOG
		log_msg("		in function xmp_fsync:\n");
		log_msg("fsync: %s\n", fpath);
		log_msg("\n");
	#endif
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef SETXATTR_LOG
		log_msg("		in function xmp_setxattr:\n");
		log_msg("setxattr: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef GETXATTR_LOG
		log_msg("		in function xmp_getxattr:\n");
		log_msg("getxattr: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}


static int xmp_listxattr(const char *path, char *list, size_t size) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef LISTXATTR_LOG
		log_msg("		in function xmp_listxattr:\n");
		log_msg("listxattr: %s\n", fpath);
		log_msg("\n");
	#endif

	res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name) {
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#ifdef REMOVEXATTR_LOG
		log_msg("		in function xmp_removexattr:\n");
		log_msg("removexattr: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create     = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr= xmp_removexattr,
#endif
};

int main(int argc, char *argv[]) {
	umask(0);

	if(argc < 4) {
		fprintf(stderr, "Incorrect usage, please try again.\n\n\t%s\n\n", USAGE);
		exit(EXIT_FAILURE);
	}

	struct encfs_state *encfs_data;

	encfs_data = (struct encfs_state *)malloc(sizeof(struct encfs_state));
    if(encfs_data == NULL) {
		perror("Error allocating heap.");
		exit(EXIT_FAILURE);
    }

	// 得到用户白名单路径和进程白名单路径
	getcwd(user_dir, PATH_MAX);
	strcat(user_dir, USER_WHITE_LIST);
	getcwd(proc_dir, PATH_MAX);
	strcat(proc_dir, PROCESS_WHITE_LIST);

	// 处理输入参数
	encfs_data->passkey = argv[argc - 1];
	encfs_data->mirror_dir = realpath(argv[argc - 2], NULL);
	encfs_data->logfile = log_open();
	char *mount_dir = argv[argc - 3];
	argc = argc - 2;

	fprintf(stdout, "Mounting %s to %s\n", encfs_data->mirror_dir, mount_dir);

	int res;

	// 初始化系统
	if((res = fuse_main(argc, argv, &xmp_oper, encfs_data))) {
		fprintf(stderr, "Internal FUSE error, please try again.\n");
		exit(EXIT_FAILURE);
	}
	printf("Filesystem successfully initialized.\n");
	return res;
}