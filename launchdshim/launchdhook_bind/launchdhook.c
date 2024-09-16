#include <fishhook.h>
#include <xpc/xpc.h>
#include <spawn.h>
#include <dirent.h>
#include <sys/mount.h>
#import <IOKit/IOKitLib.h>
#include <sys/clonefile.h>
#import <mach-o/dyld.h>

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE 0x48
#define POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE 0x4C
#define JETSAM_MULTIPLIER 3

int posix_spawnattr_set_launch_type_np(posix_spawnattr_t *attr, uint8_t launch_type);

int (*orig_csops)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);
int (*orig_csops_audittoken)(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int (*orig_posix_spawn)(pid_t * __restrict pid, const char * __restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t * __restrict attrp,
                        char *const argv[ __restrict], char *const envp[ __restrict]);
int (*orig_posix_spawnp)(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict]);
xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
int (*memorystatus_control_orig)(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);
char *sandbox_extension_issue_file(const char *extension_class, const char *path, uint32_t flags);
char *sandbox_extension_issue_mach(const char *extension_class, const char *name, uint32_t flags);

char *JB_SandboxExtensions = NULL;

int hooked_csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize) {
    int result = orig_csops(pid, ops, useraddr, usersize);
    if (result != 0) return result;
    if (ops == 0) {
        *((uint32_t *)useraddr) |= 0x4000000;
    }
    return result;
}

int hooked_csops_audittoken(pid_t pid, unsigned int ops, void * useraddr, size_t usersize, audit_token_t * token) {
    int result = orig_csops_audittoken(pid, ops, useraddr, usersize, token);
    if (result != 0) return result;
    if (ops == 0) {
        *((uint32_t *)useraddr) |= 0x4000000;
    }
    return result;
}

//void change_launchtype(posix_spawnattr_t *attrp, const char *restrict path) {
//    if (strncmp(path, "/var/jb", 7) == 0) {
//        if (attrp != 0) {
//            posix_spawnattr_set_launch_type_np(attrp, 0);
//        }
//    }
//}

int envbuf_find(const char *envp[], const char *name)
{
    if (envp) {
        unsigned long nameLen = strlen(name);
        int k = 0;
        const char *env = envp[k++];
        while (env) {
            unsigned long envLen = strlen(env);
            if (envLen > nameLen) {
                if (!strncmp(env, name, nameLen)) {
                    if (env[nameLen] == '=') {
                        return k-1;
                    }
                }
            }
            env = envp[k++];
        }
    }
    return -1;
}

int envbuf_len(const char *envp[])
{
    if (envp == NULL) return 1;

    int k = 0;
    const char *env = envp[k++];
    while (env) {
        env = envp[k++];
    }
    return k;
}

void envbuf_setenv(char **envpp[], const char *name, const char *value)
{
    if (envpp) {
        char **envp = *envpp;
        if (!envp) {
            // treat NULL as [NULL]
            envp = malloc(sizeof(const char *));
            envp[0] = NULL;
        }

        char *envToSet = malloc(strlen(name)+strlen(value)+2);
        strcpy(envToSet, name);
        strcat(envToSet, "=");
        strcat(envToSet, value);

        int existingEnvIndex = envbuf_find((const char **)envp, name);
        if (existingEnvIndex >= 0) {
            // if already exists: deallocate old variable, then replace pointer
            free(envp[existingEnvIndex]);
            envp[existingEnvIndex] = envToSet;
        }
        else {
            // if doesn't exist yet: increase env buffer size, place at end
            int prevLen = envbuf_len((const char **)envp);
            *envpp = realloc(envp, (prevLen+1)*sizeof(const char *));
            envp = *envpp;
            envp[prevLen-1] = envToSet;
            envp[prevLen] = NULL;
        }
    }
}

char **envbuf_mutcopy(const char *envp[])
{
    if (envp == NULL) return NULL;

    int len = envbuf_len(envp);
    char **envcopy = malloc(len * sizeof(char *));

    for (int i = 0; i < len-1; i++) {
        envcopy[i] = strdup(envp[i]);
    }
    envcopy[len-1] = NULL;

    return envcopy;
}
void envbuf_free(char *envp[])
{
    if (envp == NULL) return;

    int len = envbuf_len((const char**)envp);
    for (int i = 0; i < len-1; i++) {
        free(envp[i]);
    }
    free(envp);
}

void increaseJetsamLimits(posix_spawnattr_t *attrp) {
    uint8_t *attrStruct = *attrp;
        int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
        if (memlimit_active != -1) {
            *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * JETSAM_MULTIPLIER;
        }
        int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
        if (memlimit_inactive != -1) {
            *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * JETSAM_MULTIPLIER;
        }
}

void writeSandboxExtensionsToPlist() {
    remove("/var/jb/System/Library/NLR_SANDBOX_EXTENSIONS.plist");
    remove("/var/jb/System/Library/NLR_SANDBOX_EXTENSIONS.txt");
    
    char *sandboxPath = "/var/jb";
    char *filePath = "/System/Library/VideoCodecs/tmp/NLR_SANDBOX_EXTENSIONS";
    char extensionString[762];

    char *sb1 = sandbox_extension_issue_file("com.apple.app-sandbox.read", sandboxPath, 0);
    char *sb2 = sandbox_extension_issue_file("com.apple.sandbox.executable", sandboxPath, 0);
    char *sb3 = sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", "com.hrtowii.jitterd", 0);
    
    
    snprintf(extensionString, 762, "%s|%s|%s", sb1, sb2, sb3);
    
    memcpy(extensionString + 761, "d", 1);
    
    free(sb1);
    free(sb2);
    free(sb3);
    
    FILE *file = fopen(filePath, "w");
    fwrite(extensionString, 1, 762, file);
    fclose(file);
}

void strip_last_component(char *path) {
    char *last_slash = strrchr(path, '/');
    *(last_slash + 1) = '\0';
}

int hooked_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    
    if (!strncmp(path, "/var/containers/Bundle/Application/", 35)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "%s_NATHANLR", path);

        if (!access(newPath, F_OK)) {
            char dylibPath[PATH_MAX];
            snprintf(dylibPath, sizeof(dylibPath), "%s", path);
            strip_last_component(dylibPath);
            snprintf(dylibPath, sizeof(dylibPath), "%sappstorehelper.dylib", dylibPath);
            char bakPath[PATH_MAX];
            snprintf(bakPath, sizeof(bakPath), "%s.bak", path);
            rename(path, bakPath);
            clonefile(newPath, path, 0);
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", dylibPath);
            increaseJetsamLimits(attrp);
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            remove(path);
            rename(bakPath, path);
            return ret;
        }
    } else if (!strncmp(path, "/Applications/", 14)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/Applications/%s", path + 14);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (strstr(path, "/jb/Applications/")) {
        char **envc = envbuf_mutcopy((const char **)envp);
        envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
        increaseJetsamLimits(attrp);
        int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
        envbuf_free(envc);
        return ret;
    } else if (!strcmp(path, "/sbin/launchd")) {
        path = "/var/jb/System/Library/SysBins/launchd";
        argv[0] = (char *)path;
        posix_spawnattr_set_launch_type_np(attrp, 0);
    }
    
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}


int hooked_posix_spawnp(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    
    if (!strcmp(path, "/usr/libexec/xpcproxy")) {
        path = "/var/jb/System/Library/SysBins/xpcproxy";
        argv[0] = (char *)path;
        char **envc = envbuf_mutcopy((const char **)envp);
        envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/launchdhook.dylib");
        posix_spawnattr_set_launch_type_np(attrp, 0);
        int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
        envbuf_free(envc);
        return ret;
    } else if (!strncmp(path, "/Applications/", 14)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/Applications/%s", path + 14);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/System/Library/CoreServices/", 29)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/CoreServices/%s", path + 29);
        
        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    }

    return orig_posix_spawnp(pid, path, file_actions, attrp, argv, envp);
}

int hooked_posix_spawn_xpcproxy(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {

    if (!strncmp(path, "/System/Library/PrivateFrameworks/", 34)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 34);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/usr/libexec/", 13)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 13);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    }
    
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

int hooked_posix_spawnp_xpcproxy(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    
    if (!strncmp(path, "/System/Library/PrivateFrameworks/", 34)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 34);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/System/Library/Frameworks/", 27)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 27);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/usr/libexec/", 13)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 13);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/usr/sbin/", 10)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 10);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/usr/bin/", 9)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/SysBins/%s", path + 9);

        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    } else if (!strncmp(path, "/System/Library/CoreServices/", 29)) {
        char newPath[PATH_MAX];
        snprintf(newPath, sizeof(newPath), "/System/Library/VideoCodecs/CoreServices/%s", path + 29);
        
        if (!access(newPath, F_OK)) {
            path = newPath;
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/System/Library/VideoCodecs/lib/hooks/generalhook.dylib");
            increaseJetsamLimits(attrp);
            posix_spawnattr_set_launch_type_np(attrp, 0);
            int ret = orig_posix_spawnp(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    }
    
    return orig_posix_spawnp(pid, path, file_actions, attrp, argv, envp);
}

xpc_object_t hook_xpc_dictionary_get_value(xpc_object_t dict, const char *key) {
    xpc_object_t retval = xpc_dictionary_get_value_orig(dict, key);
    
    if (!strcmp(key, "Paths")) {
        if (xpc_get_type(retval) == XPC_TYPE_ARRAY) {
            xpc_array_set_string(retval, XPC_ARRAY_APPEND, "/var/jb/basebins/LaunchDaemons");
            xpc_array_set_string(retval, XPC_ARRAY_APPEND, "/var/jb/Library/LaunchDaemons");
        }
    }

    return retval;
}

int memorystatus_control_hook(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize)
{
    if (command == MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT) {
        return 0;
    }
    return memorystatus_control_orig(command, pid, flags, buffer, buffersize);
}

struct rebinding rebindings[6] = {
    {"csops", hooked_csops, (void *)&orig_csops},
    {"csops_audittoken", hooked_csops_audittoken, (void *)&orig_csops_audittoken},
    {"posix_spawn", hooked_posix_spawn, (void *)&orig_posix_spawn},
    {"posix_spawnp", hooked_posix_spawnp, (void *)&orig_posix_spawnp},
    {"xpc_dictionary_get_value", hook_xpc_dictionary_get_value, (void *)&xpc_dictionary_get_value_orig},
    {"memorystatus_control", memorystatus_control_hook, (void *)&memorystatus_control_orig},
};

struct rebinding rebindings_xpcproxy[2] = {
    {"posix_spawn", hooked_posix_spawn_xpcproxy, (void *)&orig_posix_spawn},
    {"posix_spawnp", hooked_posix_spawnp_xpcproxy, (void *)&orig_posix_spawnp},
};

typedef struct tmpfs_mount_args {
    uint64_t max_pages; /* maximum amount of memory pages to be used for this tmpfs*/
    uint64_t max_nodes; /* maximum amount of inodes in this tmpfs */
    uint64_t case_insensitive; /* 1 = case insensitive, 0 = case sensitive */
} tmpfs_mount_args_t;

__attribute__((constructor)) static void init(int argc, char **argv) {
    if (getpid() != 1) {
        unsetenv("DYLD_INSERT_LIBRARIES");
        //            sandboxExtensions = strdup(getenv("NLR_SANDBOX_EXTENSIONS"));
        //            unsetenv("NLR_SANDBOX_EXTENSIONS");
        rebind_symbols(rebindings_xpcproxy, 2);
    } else {
        if (!access("/System/Library/VideoCodecs/lib/libiosexec.1.dylib", F_OK)) {
            unmount("/System/Library/VideoCodecs/lib/", MNT_FORCE);
            unmount("/System/Library/VideoCodecs/tmp", MNT_FORCE);
            unmount("/System/Library/VideoCodecs/", MNT_FORCE);
            mount("bindfs", "/System/Library/VideoCodecs", MNT_RDONLY, (void *)"/private/var/jb/System/Library");
            struct tmpfs_mount_args arg = {.max_pages = (20000 / 16384), .max_nodes = UINT8_MAX, .case_insensitive = 0};
            mount("tmpfs", "/System/Library/VideoCodecs/tmp", 0, &arg);
            mount("bindfs", "/System/Library/VideoCodecs/lib", MNT_RDONLY, (void *)"/private/var/jb/usr/lib");
        } else {
            mount("bindfs", "/System/Library/VideoCodecs", MNT_RDONLY, (void *)"/private/var/jb/System/Library");
            struct tmpfs_mount_args arg = {.max_pages = (20000 / 16384), .max_nodes = UINT8_MAX, .case_insensitive = 0};
            mount("tmpfs", "/System/Library/VideoCodecs/tmp", 0, &arg);
            mount("bindfs", "/System/Library/VideoCodecs/lib", MNT_RDONLY, (void *)"/private/var/jb/usr/lib");
        }
        writeSandboxExtensionsToPlist();
        rebind_symbols(rebindings, 6);
    }
}
