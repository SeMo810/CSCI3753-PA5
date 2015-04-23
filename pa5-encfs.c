

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



struct fuse_operations pa5_oper = 
{
	.open = pa5_open,
	.read = pa5_read	
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
