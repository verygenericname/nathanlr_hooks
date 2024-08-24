#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>
#include "mntopts.h"

struct mntopt mopts[] = {
    MOPT_STDOPTS,
    MOPT_IGNORE_OWNERSHIP,
    MOPT_PERMISSIONS,
    { NULL }
};

void usage() {
    printf("%s [options] dir mountpoint", getprogname());
    puts("options:");
    puts("\t-o opt[,opt,...]\tMount options.");
}

int bindfs(char *from, char *to) {
    int ch, mntflags = 0;
//    while ((ch = getopt(argc, argv, "ho:")) != EOF) {
//        switch (ch) {
//        case 'o':
//            {
//                int dummy;
//                getmntopts(optarg, mopts, &mntflags, &dummy);
//            }
//            break;
//        case 'h':
//        default:
//            {
//                usage();
//                return -1;
//            }
//        }
//    }
//    argc -= optind;
//    argv += optind;

//    if (argc != 2) {
//        usage();
//        return -1;
//    }

    char *dir = (char *)calloc(MAXPATHLEN, sizeof(char));
    if (realpath(from, dir) == NULL) {
        printf("%s: failed to realpath dir %s -> %s - %s(%d)\n", getprogname(), from, dir, strerror(errno), errno);
        free(dir);
        return errno;
    }
    dir = (char *)realloc(dir, (strlen(dir) + 1) * sizeof(char));

    char *mountpoint = (char *)calloc(MAXPATHLEN, sizeof(char));
    if (realpath(to, mountpoint) == NULL) {
        printf("%s: failed to realpath mountpoint %s -> %s - %s(%d)\n", getprogname(), from, mountpoint, strerror(errno), errno);
        free(mountpoint);
        return errno;
    }
    mountpoint = (char *)realloc(mountpoint, (strlen(mountpoint) + 1) * sizeof(char));

    int mountStatus = mount("bindfs", mountpoint, mntflags, dir);
    if (mountStatus < 0)
        printf("%s: failed to mount %s -> %s - %s(%d)\n", getprogname(), dir, mountpoint, strerror(errno), errno);
    free(dir);
    free(mountpoint);
    return mountStatus == 0 ? 0 : errno;
}
