/*
 * Custom encrypted filesystem program using FUSE and xattr.
 * This is for CSCI 3753, Operating Systems, in Spring 2015, Professor Richard Han, Programming Assignment 5.
 * This is adapted from the file fusexmp.c provided with the handout for this project.
 * Author: Sean Moss (semo0788@colorado.edu)
 */

#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

/* Global settings */
char *s_rootpath;
char *s_password;
/* =============== */

/* Helper Functions */

/* Checks if a file is encrypted, 1 if encrypted or 0 otherwise */
int is_file_encrpyted(const char *path)
{
	char value[5];
	getxattr(path, "user.encrypted", value, 5);
	return (strcmp(value, "true") == 0);
}

/* Adds the encryption attr to the file, returns 1 on success, 0 on failure */
int add_encrypted_attr(const char *path)
{
	return (setxattr(path, "user.encrypted", "true", 5, 0) == 0);
}

/* Gets the path the with provided root folder, be sure to free the returned string */
char* get_root_path(const char *path)
{
	size_t len = strlen(path) + strlen(s_rootpath) + 1;
	char* retdir = (char*)malloc(len);
	
	strcpy(retdir, s_rootpath);
	strcat(retdir, path);

	return retdir;
}

/* ================ */

static int pa5_getattr(const char *path, struct stat *stbuf)
{
        int res;

        res = lstat(path, stbuf);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_access(const char *path, int mask)
{
        int res;

        res = access(path, mask);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_readlink(const char *path, char *buf, size_t size)
{
        int res;

        res = readlink(path, buf, size - 1);
        if (res == -1)
                return -errno;

        buf[res] = '\0';
        return 0;
}


static int pa5_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
        DIR *dp;
        struct dirent *de;

        (void) offset;
        (void) fi;

        dp = opendir(path);
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

static int pa5_mknod(const char *path, mode_t mode, dev_t rdev)
{
        int res;

        /* On Linux this could just be 'mknod(path, mode, rdev)' but this
           is more portable */
        if (S_ISREG(mode)) {
                res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
                if (res >= 0)
                        res = close(res);
        } else if (S_ISFIFO(mode))
                res = mkfifo(path, mode);
        else
                res = mknod(path, mode, rdev);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_mkdir(const char *path, mode_t mode)
{
        int res;

        res = mkdir(path, mode);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_unlink(const char *path)
{
        int res;

        res = unlink(path);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_rmdir(const char *path)
{
        int res;

        res = rmdir(path);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_symlink(const char *from, const char *to)
{
        int res;

        res = symlink(from, to);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_rename(const char *from, const char *to)
{
        int res;

        res = rename(from, to);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_link(const char *from, const char *to)
{
        int res;

        res = link(from, to);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_chmod(const char *path, mode_t mode)
{
        int res;

        res = chmod(path, mode);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_chown(const char *path, uid_t uid, gid_t gid)
{
        int res;

        res = lchown(path, uid, gid);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_truncate(const char *path, off_t size)
{
        int res;

        res = truncate(path, size);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_utimens(const char *path, const struct timespec ts[2])
{
        int res;
        struct timeval tv[2];

        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;

        res = utimes(path, tv);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_open(const char *path, struct fuse_file_info *fi)
{
        int res;

        res = open(path, fi->flags);
        if (res == -1)
                return -errno;

        close(res);
        return 0;
}

static int pa5_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
        int fd;
        int res;

        (void) fi;
        fd = open(path, O_RDONLY);
        if (fd == -1)
                return -errno;

        res = pread(fd, buf, size, offset);
        if (res == -1)
                res = -errno;

        close(fd);
        return res;
}

static int pa5_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        int fd;
        int res;

        (void) fi;
        fd = open(path, O_WRONLY);
        if (fd == -1)
                return -errno;

        res = pwrite(fd, buf, size, offset);
        if (res == -1)
                res = -errno;

        close(fd);
        return res;
}

static int pa5_statfs(const char *path, struct statvfs *stbuf)
{
        int res;

        res = statvfs(path, stbuf);
        if (res == -1)
                return -errno;

        return 0;
}

static int pa5_create(const char* path, mode_t mode, struct fuse_file_info* fi) {

    (void) fi;

    int res;
    res = creat(path, mode);
    if(res == -1)
        return -errno;

    close(res);

    return 0;
}


static int pa5_release(const char *path, struct fuse_file_info *fi)
{
        /* Just a stub.  This method is optional and can safely be left
           unimplemented */

        (void) path;
        (void) fi;
        return 0;
}

static int pa5_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
        /* Just a stub.  This method is optional and can safely be left
           unimplemented */

        (void) path;
        (void) isdatasync;
        (void) fi;
        return 0;
}

#ifdef HAVE_SETXATTR
static int pa5_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
        int res = lsetxattr(path, name, value, size, flags);
        if (res == -1)
                return -errno;
        return 0;
}

static int pa5_getxattr(const char *path, const char *name, char *value,
                        size_t size)
{
        int res = lgetxattr(path, name, value, size);
        if (res == -1)
                return -errno;
        return res;
}

static int pa5_listxattr(const char *path, char *list, size_t size)
{
        int res = llistxattr(path, list, size);
        if (res == -1)
                return -errno;
        return res;
}

static int pa5_removexattr(const char *path, const char *name)
{
        int res = lremovexattr(path, name);
        if (res == -1)
                return -errno;
        return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations pa5_oper = {
        .getattr        = pa5_getattr,
        .access         = pa5_access,
        .readlink       = pa5_readlink,
        .readdir        = pa5_readdir,
        .mknod          = pa5_mknod,
        .mkdir          = pa5_mkdir,
        .symlink        = pa5_symlink,
        .unlink         = pa5_unlink,
        .rmdir          = pa5_rmdir,
        .rename         = pa5_rename,
        .link           = pa5_link,
        .chmod          = pa5_chmod,
        .chown          = pa5_chown,
        .truncate       = pa5_truncate,
        .utimens        = pa5_utimens,
        .open           = pa5_open,
        .read           = pa5_read,
        .write          = pa5_write,
        .statfs         = pa5_statfs,
        .create         = pa5_create,
        .release        = pa5_release,
        .fsync          = pa5_fsync,
#ifdef HAVE_SETXATTR
        .setxattr       = pa5_setxattr,
        .getxattr       = pa5_getxattr,
        .listxattr      = pa5_listxattr,
        .removexattr    = pa5_removexattr,
#endif
};

int main(int argc, char **argv)
{
	if (argc < 4)
	{
		printf("Usage: ./pa5-encfs [Options] <Key Phrase> <Mirror Directory> <Mount Point>\n");
		return EXIT_FAILURE;
	}

	if ((s_rootpath = realpath(argv[argc - 1], NULL)) == NULL)
	{
		printf("ERROR: Please enter a valid mirror directory name.\n");
		return EXIT_FAILURE;
	}
	
	if ((s_password = argv[argc - 3]) == NULL)
	{
		printf("ERROR: Please enter a valid password.\n");
		return EXIT_FAILURE;
	}

	argv[argc - 3] = argv[argc - 2];
	argc -= 2;

	umask(0);
	return fuse_main(argc, argv, &pa5_oper, NULL);
}
