#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

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

#include "encfuse.h"

FILE *log_open() {
    FILE *logfile;
    
    logfile = fopen("logfile.log", "w");
    if (logfile == NULL) {
		perror("logfile");
		exit(EXIT_FAILURE);
    }
    
	// 设置logfile每次输出一行
    setvbuf(logfile, NULL, _IOLBF, 0);

    return logfile;
}

void log_msg(const char *format, ...) {
    va_list ap;
    va_start(ap, format);

	// 使用参数列表发送格式化输出到流 stream 中
    vfprintf(ENCFS_DATA->logfile, format, ap);
}

uint32_t get_encfs_uid() {
	return fuse_get_context()->uid;
}

static char * ftemp(const char *path, const char *suffix){
	char * temp_path;
	int len = strlen(path) + strlen(suffix) + 1;
	if( !(temp_path = (char *)malloc(sizeof(char)* len)) ){
		fprintf(stderr, "Error allocating temproary file in %s function.\n", suffix);
		exit(EXIT_FAILURE);
	}
	temp_path[0] = '\0';
	strcat(strcat(temp_path,path),suffix);
	return temp_path;
}

/**
 * 获取文件的全路径
 * @param fpath 挂载根路径
 * @param path 当前文件相对路径
 * @return 得到当前文件的绝对路径(fpath)
*/
static void xmp_getfullpath(char fpath[PATH_MAX], const char *path)
{
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
static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res=0;
	int action = COPY;
	ssize_t vsize = 0;
	char *tval = NULL;

	time_t    atime;   	/* time of last access */
	time_t    mtime;   	/* time of last modification */
    time_t    tctime;   	/* time of last status change */
    dev_t     t_dev;     	/* ID of device containing file */
    ino_t     t_ino;     	/* inode number */
    mode_t    mode;    	/* protection */
    nlink_t   t_nlink;   	/* number of hard links */
    uid_t     t_uid;     	/* user ID of owner */
    gid_t     t_gid;     	/* group ID of owner */
    dev_t     t_rdev;    	/* device ID (if special file) */

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1){
		return -errno;
	}
	
	/* is it a regular file? */
	if (S_ISREG(stbuf->st_mode)){

		/* These file characteristics don't change after decryption so just storing them */
		atime = stbuf->st_atime;
		mtime = stbuf->st_mtime;
		tctime = stbuf->st_ctime;
		t_dev = stbuf->st_dev;
		t_ino = stbuf->st_ino;
		mode = stbuf->st_mode;
		t_nlink = stbuf->st_nlink;
		t_uid = stbuf->st_uid;
		t_gid = stbuf->st_gid;
		t_rdev = stbuf->st_rdev;

		/* Get size of flag value and value itself */
		vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
		tval = (char *)malloc(sizeof(*tval)*(vsize));
		vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tval, vsize);
		
		fprintf(stderr, "Xattr Value: %s\n", tval);

		/* If the specified attribute doesn't exist or it's set to false */
		if (vsize < 0 || memcmp(tval, "false", 5) == 0){
			if(errno == ENODATA){
				fprintf(stderr, "No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
			}
			fprintf(stderr, "File unencrypted, reading...\n");
			action = COPY;
		}
		/* If the attribute exists and is true get size of decrypted file */
		else if (memcmp(tval, "true", 4) == 0){
			fprintf(stderr, "file encrypted, decrypting...\n");
			action = DECRYPT;
		}

		const char *tpath = ftemp(fpath, ".getattr");
		FILE *dfd = fopen(tpath, "wb+");
		FILE *fd = fopen(fpath, "rb");

		fprintf(stderr, "fpath: %s\ntpath: %s\n", fpath, tpath);

		if(action >= 0 && !do_crypt(fd, dfd, action, ENCFS_DATA->passkey)){
			fprintf(stderr, "getattr do_crypt failed\n");
    	}

		fclose(fd);
		fclose(dfd);

		/* Get size of decrypted file and store in stat struct */
		res = lstat(tpath, stbuf);
		if (res == -1){
			return -errno;
		}

		/* Put info about file into stat struct*/
		stbuf->st_atime = atime;
		stbuf->st_mtime = mtime;
		stbuf->st_ctime = tctime;
		stbuf->st_dev = t_dev;
		stbuf->st_ino = t_ino;
		stbuf->st_mode = mode;
		stbuf->st_nlink = t_nlink;
		stbuf->st_uid = t_uid;
		stbuf->st_gid = t_gid;
		stbuf->st_rdev = t_rdev;

		free(tval);
		remove(tpath);
	}
	
	return 0;
}

/**
 * 查看文件是否具有某种权限（读，写，执行）
 * @param path 文件路径
 * @param mask 权限类型
 * @return 0/other: 成功/出错
*/
static int xmp_access(const char *path, int mask)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);
	
	#if ACCESS_LOG
		log_msg("		in function xmp_access:\n");
		log_msg("Access: %s\n", fpath);
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
static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if READ_LINK_LOG
		log_msg("		in function xmp_readlink:\n");
		log_msg("ReadLink: %s\n", fpath);
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
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if READ_DIR_LOG
		log_msg("		in function xmp_readdir:\n");
		log_msg("Read Dir: %s\n", fpath);
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

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if MKNOD_LOG
		log_msg("		in function xmp_mknod:\n");
		log_msg("Mknode: %s\n", fpath);
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

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if MKDIR_LOG
		log_msg("		in function xmp_mkdir:\n");
		log_msg("MkDir: %s\n", fpath);
		log_msg("\n");
	#endif

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if UNLINK_LOG
		log_msg("		in function xmp_unlink:\n");
		log_msg("Unlink: %s\n", fpath);
		log_msg("\n");
	#endif

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if RM_DIR_LOG
		log_msg("		in function xmp_rmdir:\n");
		log_msg("Rm Dir: %s\n", fpath);
		log_msg("\n");
	#endif

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#if SYMLINK_LOG
		log_msg("		in function xmp_symlink:\n");
		log_msg("Symlink: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = symlink(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#if RENAME_LOG
		log_msg("		in function xmp_rename:\n");
		log_msg("Rename: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = rename(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	char ffrom[PATH_MAX], fto[PATH_MAX];
	xmp_getfullpath(ffrom, from);
	xmp_getfullpath(fto, to);

	#if LINK_LOG
		log_msg("		in function xmp_link:\n");
		log_msg("Link: %s -> %s\n", ffrom, fto);
		log_msg("\n");
	#endif

	res = link(ffrom, fto);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if CHMOD_LOG
		log_msg("		in function xmp_chmod:\n");
		log_msg("chmod: %s\n", fpath);
		log_msg("\n");
	#endif

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if CHOWN_LOG
		log_msg("		in function xmp_chown:\n");
		log_msg("Chown: %s\n", fpath);
		log_msg("\n");
	#endif

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if TRUNCATE_LOG
		log_msg("		in function xmp_truncate:\n");
		log_msg("Truncate: %s\n", fpath);
		log_msg("\n");
	#endif

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if UTIMENS_LOG
		log_msg("		in function xmp_utimens:\n");
		log_msg("uTimes: %s\n", fpath);
		log_msg("\n");
	#endif

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);
	int user_open_access = check_user_open_access(fpath);

	#ifdef OPEN_LOG
		log_msg("		in function xmp_open\n");
		log_msg("Open: %s\n", fpath);
		log_msg("user open access is %d\n", user_open_access);
	#endif

	if(user_open_access == 0) {
		#ifdef OPEN_LOG
			log_msg("can't open file, permission denied\n");
		#endif
		return -1;
	}

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
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
	(void)fi;
	int res = 0;
	int action;
	ssize_t vsize = 0;
	char *tval = NULL;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if READ_LOG
		log_msg("		in function xmp_read:\n");
		log_msg("fpath:%s\n", fpath);
		log_msg("Read:%i\n", size);
	#endif

	vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tval = (char *)malloc(sizeof(*tval)*(vsize));
	vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tval, vsize);

	fprintf(stderr, "Size: %zu, offset: %zu.\n", size, offset);

	/* If the specified attribute doesn't exist or it's set to false */
	if (vsize < 0 || memcmp(tval, "false", 5) == 0){
		if(errno == ENODATA){
			fprintf(stderr, "Read: No %s attribute set\n", XATRR_ENCRYPTED_FLAG);
		}
		action = COPY;
	}
	else if (memcmp(tval, "true", 4) == 0){
		action = DECRYPT;
		fprintf(stderr, "Read: file is encrypted, need to decrypt\n");
	}

	const char *tpath = ftemp(fpath, ".read");
	FILE *dfd = fopen(tpath, "wb+");
	FILE *fd = fopen(fpath, "rb");

	int write_bytes = do_crypt(fd, dfd, action, ENCFS_DATA->passkey);
	if(write_bytes == 0) {
		fprintf(stderr, "Encryption failed, error code: %d\n", errno);
    }

    if(fseek(dfd, offset, SEEK_SET) == -1) {
		fprintf(stderr, "can't fseek, error code: %d\n", errno);
	}
	/**
	 * ftell(): 获取文件当前的读写位置偏移量
	*/
	/* Fuse内核的读的块最大为 32KB = 131072B */
   	res = fread(buf, 1, size, dfd);
    if (res == -1) {
		res = -errno;
		fprintf(stderr, "read to buf error, error code: %d\n", errno);
	}

	fclose(fd);
	fclose(dfd);
	remove(tpath);
	free(tval);

	// 下面是不通过中间文件解密，但是读取大文件时 EVP_CipherFinal_ex 报错，暂时未解决
	// FILE *fd = fopen(fpath, "rb");
	// if(fd == NULL) {
	// 	fprintf(stderr, "open file error, error code: %d\n", errno);
	// }

	// if(fseek(fd, offset, SEEK_SET) == -1) {
	// 	fprintf(stderr, "fseek error, error code: %d\n", errno);
	// }

	// if(buf_crypt(fd, size, buf, &res, action, ENCFS_DATA->passkey) == 0) {
	// 	res = -errno;
	// 	fprintf(stderr, "buf_crypt error, error code: %d\n", errno);
	// }

	// fclose(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	(void) fi;
	(void) offset;

	int res=0;
	int action = COPY;

	ssize_t vsize = 0;
	char *tval = NULL;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if WRITE_LOG
		log_msg("		in function xmp_write:\n");
		log_msg("Write: %i\n",  size);
	#endif

	vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, NULL, 0);
	tval = (char *)malloc(sizeof(*tval)*(vsize));
	vsize = getxattr(fpath, XATRR_ENCRYPTED_FLAG, tval, vsize);

	if (vsize < 0 || memcmp(tval, "false", 5) == 0){
		if(errno == ENODATA){
			fprintf(stderr, "Encryption flag not set, file cannot be read.\n");
		}
		fprintf(stderr, "File unencrypted, reading...\n");
	} else if (memcmp(tval, "true", 4) == 0){
		fprintf(stderr, "File encrypted, decrypting...\n");
		action = DECRYPT;
	}


	/* If the file to be written to is encrypted */
	if (action == DECRYPT){
		FILE *fd = fopen(fpath, "rb+");
		const char *tpath = ftemp(fpath, ".write");
		FILE *dfd = fopen(tpath, "wb+");

		fseek(fd, 0, SEEK_END);
		fseek(fd, 0, SEEK_SET);

		if(!do_crypt(fd, dfd, DECRYPT, ENCFS_DATA->passkey)){
			fprintf(stderr, "Decryption failed, error code: %d\n", res);
    	}

    	fseek(fd, 0, SEEK_SET);

    	res = fwrite(buf, 1, size, dfd);
    	if (res == -1)
		res = -errno;

		fseek(dfd, 0, SEEK_SET);

		if(!do_crypt(dfd, fd, ENCRYPT, ENCFS_DATA->passkey)){
			fprintf(stderr, "Encryption failed, error code: %d\n", res);
		}

		fclose(fd);
		fclose(dfd);
		remove(tpath);
	} else if (action == COPY){
		int fd1;
		fprintf(stderr, "File unencrypted, reading...\n");

		fd1 = open(fpath, O_WRONLY);
		if (fd1 == -1)
			return -errno;

		res = pwrite(fd1, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd1);
   	}
   	
	free(tval);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if STATFS_LOG
		log_msg("		in function xmp_statfs:\n");
		log_msg("Statfs: %s\n", fpath);
		log_msg("\n");
	#endif

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	#if CREATE_LOG
		log_msg("		in function xmp_create:\n");
		log_msg("Create: %s\n", fpath);
	#endif
	
    (void) fi;
    (void) mode;

	FILE *fd = fopen(fpath, "wb+");

	fprintf(stderr, "CREATE: fpath: %s\n", fpath);

	if(!do_crypt(fd, fd, ENCRYPT, ENCFS_DATA->passkey)){
		fprintf(stderr, "Create: do_crypt failed\n");
    }

	fprintf(stderr, "Create: encryption done correctly\n");

	fclose(fd);

	char flag[5] = "true";
	if(setxattr(fpath, XATRR_ENCRYPTED_FLAG, flag, 5, 0)){
    	fprintf(stderr, "error setting xattr of file %s\n", fpath);
    	return -errno;
   	}
   	fprintf(stderr, "Create: file xatrr correctly set %s\n", fpath);
   
    return 0;
}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
	xmp_getfullpath(fpath, path);

	int res = lremovexattr(fpath, name);
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
	.utimens	= xmp_utimens,
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

int main(int argc, char *argv[])
{
	umask(0);

	if(argc < 4){
		fprintf(stderr, "Incorrect usage, please try again.\n\n\t%s\n\n", USAGE);
		exit(EXIT_FAILURE);
	}

	struct encfs_state *encfs_data;

	encfs_data = (struct encfs_state *)malloc(sizeof(struct encfs_state));
    if(encfs_data == NULL) {
		perror("Error allocating heap.");
		exit(EXIT_FAILURE);
    }

	// Parsing input args
	
	encfs_data->passkey = argv[argc - 1];
	encfs_data->mirror_dir = realpath(argv[argc - 2], NULL);
	char *mount_dir = argv[argc - 3];
	argc = argc - 2;

	encfs_data->logfile = log_open();
	// encfs_data->userfile = user_open(encfs_data->mirror_dir);
	

	/**
	 * ./encfuse ./mnt ./test 12345
	 * ./encfuse -o allow_other ./mnt ./test 12345
	*/

	fprintf(stdout, "Mounting %s to %s\n", encfs_data->mirror_dir, mount_dir);

	int res;

	// Initializing filesystem
	if( (res = fuse_main(argc, argv, &xmp_oper, encfs_data)) ) {
		fprintf(stderr, "Internal FUSE error, please try again.\n");
		exit(EXIT_FAILURE);
	}

	// SUCCESS!
	else printf("Filesystem successfully initialized.\n");
	return res;
}