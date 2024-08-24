// fix sudo and su

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <spawn.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/param.h>

#define SIGABRT 6
#define OS_REASON_SIGNAL        2
#define OS_REASON_DYLD          6
#define DYLD_EXIT_REASON_OTHER                  9

void abort_with_payload(uint32_t reason_namespace, uint64_t reason_code,
    void *payload, uint32_t payload_size,
    const char *reason_string, uint64_t reason_flags)
    __attribute__((noreturn, cold));

#define    ASSERT(e)    (__builtin_expect(!(e), 0) ?\
 ((void)fprintf(stderr, "%s:%d: failed ASSERTion `%s'\n", __FILE_NAME__, __LINE__, #e),\
 abort_with_payload(OS_REASON_DYLD,DYLD_EXIT_REASON_OTHER,NULL,0, #e, 0)) : (void)0)


extern char **environ;

#define POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE 1

enum {
    PERSONA_INVALID      = 0,
    PERSONA_GUEST        = 1,
    PERSONA_MANAGED      = 2,
    PERSONA_PRIV         = 3,
    PERSONA_SYSTEM       = 4,
    PERSONA_DEFAULT      = 5,
    PERSONA_SYSTEM_PROXY = 6,
    PERSONA_SYS_EXT      = 7,
    PERSONA_ENTERPRISE   = 8,

    PERSONA_TYPE_MAX     = PERSONA_ENTERPRISE,
};

#define PERSONA_INFO_V1       1
#define PERSONA_INFO_V2       2

struct kpersona_info {
    /* v1 fields */
    uint32_t persona_info_version;

    uid_t    persona_id;
    int      persona_type;
    gid_t    persona_gid; /* unused */
    uint32_t persona_ngroups; /* unused */
    gid_t    persona_groups[NGROUPS]; /* unused */
    uid_t    persona_gmuid; /* unused */
    char     persona_name[MAXLOGNAME + 1];

    /* v2 fields */
    uid_t    persona_uid;
} __attribute__((packed));

extern int kpersona_find_by_type(int persona_type, uid_t *id, size_t *idlen);
extern int kpersona_getpath(uid_t id, char path[MAXPATHLEN]);
extern int kpersona_pidinfo(pid_t id, struct kpersona_info *info);
extern int kpersona_info(uid_t id, struct kpersona_info *info);
extern int kpersona_find(const char *name, uid_t uid, uid_t *id, size_t *idlen);
extern int kpersona_alloc(struct kpersona_info *info, uid_t *id);


int available_persona_id()
{
    struct kpersona_info info={PERSONA_INFO_V1};
    ASSERT(kpersona_pidinfo(getpid(), &info) == 0);

    int current_persona_id = info.persona_id;

    for(int t=1; t<=PERSONA_TYPE_MAX; t++)
    {
        uid_t personas[128]={0};
        size_t npersonas = 128;

        if(kpersona_find_by_type(t, personas, &npersonas) <= 0)
            continue;

        for(int i=0; i<npersonas; i++)
        {
            if(personas[i] != current_persona_id)
                return personas[i];
        }
    }
    return 0;
}

int posix_spawnattr_set_persona_np(const posix_spawnattr_t* __restrict, uid_t, uint32_t);
int posix_spawnattr_set_persona_uid_np(const posix_spawnattr_t* __restrict, uid_t);
int posix_spawnattr_set_persona_gid_np(const posix_spawnattr_t* __restrict, gid_t);

int main(int __unused argc, char* argv[]) {
  setenv("SUID_FIX", "1", 1);
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  int persona_id = available_persona_id();
  ASSERT(persona_id != 0);
  posix_spawnattr_set_persona_np(&attr, persona_id, POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE);
  posix_spawnattr_set_persona_uid_np(&attr, 0);
  posix_spawnattr_set_persona_gid_np(&attr, 0);
  int pid = 0;
    if(strcmp(argv[0], "login") == 0) {
        int ret = posix_spawnp(&pid, "/var/jb/usr/bin/login", NULL, &attr, argv, environ);
    } else {
        int ret = posix_spawnp(&pid, argv[0], NULL, &attr, argv, environ);
    }
  waitpid(pid, NULL, 0);
  return 0;
}
