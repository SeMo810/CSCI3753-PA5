

#define FUSE_USE_VERSION 28
#define _XOPEN_SOURCE 500

#include <limits.h>
#include <stdio.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

struct pa5_state 
{
	char *rootdir;
	char *password;
};
#define STATE_DATA ((struct pa5_state *) fuse_get_context()->private_data)

/* =============== Helper Functions =============== */
static void get_full_path(char fpath[PATH_MAX], const char *path)
{
	strcpy(fpath, STATE_DATA->rootdir);
	strncat(fpath, path, PATH_MAX);
}
/* ================================================ */

int pa5_getattr(const char *path, struct stat *stbuf)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);
        
        res = lstat(fpath, stbuf);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_access(const char *path, int mask)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = access(fpath, mask);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_readlink(const char *path, char *buf, size_t size)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = readlink(fpath, buf, size - 1);
        if (res == -1)
                return -errno;

        buf[res] = '\0';
        return 0;
}

int pa5_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];

	get_full_path(fpath, path);

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

int pa5_mkdir(const char *path, mode_t mode)
{
        int res;
	char fpath[PATH_MAX];

	get_full_path(fpath, path);

        res = mkdir(fpath, mode);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_mknod(const char *path, mode_t mode, dev_t rdev)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

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

int pa5_unlink(const char *path)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = unlink(fpath);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_rmdir(const char *path)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = rmdir(fpath);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_symlink(const char *from, const char *to)
{
        int res;
	char fpath[PATH_MAX];
	char tpath[PATH_MAX];
	get_full_path(fpath, from);
	get_full_path(tpath, to);

        res = symlink(fpath, tpath);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_rename(const char *from, const char *to)
{
        int res;
	char fpath[PATH_MAX];
        char tpath[PATH_MAX];
        get_full_path(fpath, from);
        get_full_path(tpath, to);
        
        res = rename(fpath, tpath);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_link(const char *from, const char *to)
{
        int res;
	char fpath[PATH_MAX];
        char tpath[PATH_MAX];
        get_full_path(fpath, from);
        get_full_path(tpath, to);

        res = link(fpath, tpath);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_chmod(const char *path, mode_t mode)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = chmod(fpath, mode);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_chown(const char *path, uid_t uid, gid_t gid)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = lchown(fpath, uid, gid);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_truncate(const char *path, off_t size)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = truncate(fpath, size);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_utimens(const char *path, const struct timespec ts[2])
{
        int res;
        struct timeval tv[2];
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        tv[0].tv_sec = ts[0].tv_sec;
        tv[0].tv_usec = ts[0].tv_nsec / 1000;
        tv[1].tv_sec = ts[1].tv_sec;
        tv[1].tv_usec = ts[1].tv_nsec / 1000;

        res = utimes(fpath, tv);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_open(const char *path, struct fuse_file_info *fi)
{
	char fpath[PATH_MAX];
    
	get_full_path(fpath, path);
    
	int fd = open(fpath, fi->flags);
	if (fd < 0)
		return -errno;
	
	close(fd);
	return 0;
}

int pa5_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
	int res = 0;
	char fpath[PATH_MAX];

	get_full_path(fpath, path);

	(void) fi;
	int fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res < 0)
		res = -errno;

	close(fd);
	return res;
}

int pa5_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        int fd;
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        (void) fi;
        fd = open(fpath, O_WRONLY);
        if (fd == -1)
                return -errno;

        res = pwrite(fd, buf, size, offset);
        if (res == -1)
                res = -errno;

        close(fd);
        return res;
}

int pa5_statfs(const char *path, struct statvfs *stbuf)
{
        int res;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        res = statvfs(fpath, stbuf);
        if (res == -1)
                return -errno;

        return 0;
}

int pa5_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
        (void) fi;
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        int res;
        res = creat(fpath, mode);
        if(res == -1)
                return -errno;
        
        close(res);

        return 0;
}

int pa5_release(const char *path, struct fuse_file_info *fi)
{
        /* Just a stub.  This method is optional and can safely be left
           unimplemented */

        (void) path;
        (void) fi;
        return 0;
}

int pa5_fsync(const char *path, int isdatasync,
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
int pa5_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        int res = lsetxattr(fpath, name, value, size, flags);
        if (res == -1)
                return -errno;
        return 0;
}

int pa5_getxattr(const char *path, const char *name, char *value,
                        size_t size)
{
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        int res = lgetxattr(fpath, name, value, size);
        if (res == -1)
                return -errno;
        return res;
}

int pa5_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        int res = llistxattr(fpath, list, size);
        if (res == -1)
                return -errno;
        return res;
}

int pa5_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];

        get_full_path(fpath, path);

        int res = lremovexattr(fpath, name);
        if (res == -1)
                return -errno;
        return 0;
}
#endif /* HAVE_SETXATTR */

struct fuse_operations pa5_oper = {
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

/* Command Line: "./pa5_encfs [Options] <Password> <Mirror Directory> <Mount Point>" */
int main(int argc, char** argv)
{
	struct pa5_state settings;

	if (argc < 4)
	{
		printf("ERROR: Usage: \"./pa5_encfs [Options] <Password> <Mirror Directory> <Mount Point>\"\n");
		return EXIT_FAILURE;
	}

	char *password = argv[argc - 3];
	char *mirror = argv[argc - 2];
	char *mount = argv[argc - 1];

	if ((settings.rootdir = realpath(mount, NULL)) == NULL)
	{
		printf("ERROR: Please enter a valid directory for the mount point.\n");
		return EXIT_FAILURE;
	}
	if ((settings.password = password) == NULL)
	{
		printf("ERROR: Please enter a non-empty password for encryption.\n");
		return EXIT_FAILURE;
	}

	argv[argc - 3] = argv[argc - 2];
	argv[argc - 2] = argv[argc - 1] = NULL;
	argc -= 2;

	return fuse_main(argc, argv, &pa5_oper, &settings);
}
