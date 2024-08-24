#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern char **environ;

int main() {
    pid_t pid;
    char *argv[] = {
        "/var/jb/usr/bin/uicache",
        "-a",
        NULL
    };
    posix_spawn(&pid, argv[0], NULL, NULL, argv, environ);
    waitpid(pid, NULL, 0);

    exit(0);
}
