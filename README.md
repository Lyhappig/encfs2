## encfs 透明文件加密系统

### 简介

基于fuse的用户态文件系统，实现了基于SM4—CTR的透明加密，可以拦截非法用户和进程

缺点是效率比较低

### 环境要求

测试操作系统：CentOS 7/8

### 依赖

#### fuse

```shell
yum install -y fuse fuse-devel
```

#### openssl

```shell
yum install -y openssl openssl-devel
```

#### gmssl

采用 Gmssl-3.0

```shell
wget https://github.com/guanzhi/GmSSL/archive/refs/tags/v3.0.0.tar.gz
```

### 准备

#### Allow Other User

FUSE 默认只有挂载文件系统的用户可以访问挂载点中的文件，allow_other 选项可以让其他用户也可以访问挂载点上的文件。当 root 用户挂载时，该选项会自动启用，无需显式指定。而如果是普通用户挂载，则需要修改 /etc/fuse.conf，在该配置文件中开启 user_allow_other 配置选项，才能在普通用户挂载时启用 allow_other。

```shell
vi /etc/fuse.conf 文件
# 开启 'user_allow_other'
```

### Building

`build` 项目

```shell
make all
```

清理 `building`

```shell
make clean
```

### 使用

#### 挂载与卸载

采用如下格式的命令挂载系统

```shell
./bin/encfs <flags> ... <mount directory> <mirror directory> <keyphrase>
```

例如

```shell
./bin/encfs ./mnt ./test 12345

./bin/encfs -o allow_other ./mnt ./test 12345
```

脚本执行挂载： `./run.sh`

取消挂载可以使用

```shell
umount <Mount Point>
```

或者

```shell
fuermount -u <Mount Point>
```

若文件系统遇到错误，需要强制取消挂载

```shell
ps aux | grep "mnt"
kill -9 pid
umount -l <Mount Point>
```

脚本执行卸载： `./stop.sh`

### Debug

系统运行中开启 stdout/stderr 输出流：

```shell
./encfuse -f ./mnt ./test 12345
```


### 查看挂载信息

执行

```shell
mount
```

或者

```shell
cat /proc/mounts
```

### 一些报错

需要加上nonempty参数

```shell
fuse: mountpoint is not empty
fuse: if you are sure this is safe, use the 'nonempty' mount option
Internal FUSE error, please try again.
```









