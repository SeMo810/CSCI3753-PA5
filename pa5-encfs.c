/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fusexmp.c -o fusexmp `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

struct pa5_state
{
	char *rootdir;
	char *password;
};
#define STATE_DATA ((struct pa5_state *) fuse_get_context()->private_data)

/* Helper Functions */
static void get_full_path(char fpath[512], const char *path)
{
	strcpy(fpath, STATE_DATA->rootdir);
	strcat(fpath, path);
}

/* Sets the file to be encrypted, returns 1 on success. */
static int add_encrypted_flag(const char* path)
{
	return (setxattr(path, "user.encrypted", "true", 5, 0) == 0);
}

/* Gets the encryped status of the file, returns 1 if encrypted, 0 otherwise. */
static int is_encrypted(const char* path)
{
	char value[5];
	getxattr(path, "user.encrypted", value, 5);
	return (strcmp(value, "true") == 0);
}
/* ================================ */

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

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

	char fpath[512] = { 0 };
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

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	char fpath[512] = { 0 };
	char tpath[512] = { 0 };
	get_full_path(fpath, from);
	get_full_path(tpath, to);

	res = symlink(fpath, tpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	char fpath[512] = { 0 };
	char tpath[512] = { 0 };
	get_full_path(fpath, from);
	get_full_path(tpath, to);

	res = rename(fpath, tpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;
	char fpath[512] = { 0 };
	char tpath[512] = { 0 };
	get_full_path(fpath, from);
	get_full_path(tpath, to);

	res = link(fpath, tpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];

	char fpath[512] = { 0 };
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

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);
	char tmppath[512] = { 0 };
	get_full_path(tmppath, "/.xmp_crypt_tmp");

	(void) fi;

	if (is_encrypted(fpath))
	{
		FILE *in = fopen(fpath, "rb");
		if (!in)
		{
			printf("ERROR: Could not open file for reading: %d.\n", -errno);
			return -errno;
		}
		FILE *tmp = fopen(tmppath, "w");
		if (!tmp)
		{
			fclose(in);
			printf("ERROR: Could not open temporary decryption file: %d.\n", -errno);
			return -errno;
		}

		fseek(in, 0L, SEEK_END);
		int sz = ftell(in); /* Get the file size, if there is nothing, then dont decrypt it. */
		fseek(in, 0L, SEEK_SET);
		if (sz != 0 && !do_crypt(in, tmp, 0, STATE_DATA->password))
		{
			fclose(in);
			fclose(tmp);
			printf("ERROR: do_crypt failed to decrypt a file: %d.\n", -errno);
			remove(tmppath);
			return -errno;
		}

		fclose(in);
		fseek(tmp, 0L, SEEK_SET);
		fclose(tmp);

		int fd = open(tmppath, O_RDONLY);
		if (fd == -1)
		{
			printf("ERROR: Could not open temporary decryption file for readback: %d.\n", -errno);
			remove(tmppath);
			return -errno;
		}

		res = pread(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
		remove(tmppath);
	}
	else
	{
		int fd = open(fpath, O_RDONLY);
		if (fd == -1)
		{
			printf("ERROR: Could not open file for reading: %d.\n", -errno);
			return -errno;
		}

		res = pread(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
	}

	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);
	char tmppath[512] = { 0 };
	get_full_path(tmppath, "/.xmp_crypt_tmp");

	(void) fi;

	if (is_encrypted(fpath))
	{
		FILE *tmp = fopen(tmppath, "w+");
		if (!tmp)
		{
			printf("Could not open temp file to write to: %d.\n", errno);
			return -errno;
		}

		FILE *out = fopen(fpath, "rb");
		if (!out)
		{
			fclose(tmp);
			printf("Could not open file for reading in existing data: %d.\n", errno);
			return -errno;
		}
		fseek(out, 0L, SEEK_END);
		int len = ftell(out);
		printf("DEBUG: reporting length of %d\n", len);
		fseek(out, 0L, SEEK_SET);
		if (len > 0) /* If there is already existing data. */
		{
			if (!do_crypt(out, tmp, 0, STATE_DATA->password))
			{
				fclose(tmp);
				fclose(out);
				remove(tmppath);
				printf("Failed to decrypt existing data: %d.\n", errno);
				return -errno;
			}
		}
		fseek(tmp, len, SEEK_SET);
		fputs(buf, tmp);
		fclose(tmp);
		fclose(out);
		tmp = NULL;
		out = NULL;

		tmp = fopen(tmppath, "r");
		if (!tmp)
		{
			printf("Could not open temp file for reading out of: %d.\n", -errno);
			remove(tmppath);
			return -errno;
		}
		fseek(tmp, 0L, SEEK_SET);

		out = fopen(fpath, "wb");
		if (!out)
		{
			fclose(tmp);
			remove(tmppath);
			printf("Could not open output file for writing: %d.\n", -errno);
			return -errno;
		}
		if (!do_crypt(tmp, out, 1, STATE_DATA->password))
		{
			fclose(tmp);
			fclose(out);
			remove(tmppath);
			printf("Could not encrypt file: %d.\n", -errno);
			return -errno;
		}

		fclose(tmp);
		fclose(out);
		remove(tmppath);
	}
	else
	{
		int fd = open(fpath, O_WRONLY);
		if (fd == -1)
			return -errno;

		res = pwrite(fd, buf, size, offset);
		if (res == -1)
			res = -errno;

		close(fd);
	}

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi)
{
  (void) fi;

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	int res;
	res = creat(fpath, mode);
	if(res == -1)
		return -errno;

	close(res);

	add_encrypted_flag(fpath);

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

	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[512] = { 0 };
	get_full_path(fpath, path);

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
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

	struct pa5_state *settings;
	settings = (struct pa5_state *)malloc(sizeof(struct pa5_state));

	if (argc < 4)
	{
		printf("Usage: ./pa5-encfs [Options] <password> <mirror> <mount>\n");
		return EXIT_FAILURE;
	}

	char *password = argv[argc - 3];
	char *mirror = argv[argc - 2];
	char *mount = argv[argc - 1];

	if (mirror[0] == '-' || mount[0] == '-')
	{
		printf("Error: The mount and mirror directories must not start with a hyphen.\n");
		return EXIT_FAILURE;
	}

	if ((settings->rootdir = realpath(mount, NULL)) == NULL)
	{
		printf("Error: Please enter a valid mount path.");
		return EXIT_FAILURE;
	}
	if ((settings->password = password) == NULL)
	{
		printf("Error: Please enter a non-empty password.\n");
		return EXIT_FAILURE;
	}

	argv[argc - 3] = argv[argc - 2];
	argc -= 2;

	int ret = fuse_main(argc, argv, &xmp_oper, settings);
	free(settings);
	return ret;
}
