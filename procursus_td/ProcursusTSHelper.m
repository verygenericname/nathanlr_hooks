// fork() and rootless fix for Procursus bootstrap (named libTS2JailbreakEnv.dylib)
// there's lots of stuff not cleaned up, feel free to play around
// Requires fishhook from https://github.com/khanhduytran0/fishhook
// Usage: inject to libiosexec.dylib, ensure all binaries have get-task-allow entitlement

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach_init.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/syslimits.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <libgen.h>
#include <mach-o/fat.h>
#include <fishhook.h>
#import <Foundation/Foundation.h>
#import <libproc.h>

extern char **environ;

#define printf(...) // __VA_ARGS__

int apply_coretrust_bypass_wrapper(const char *inputPath, const char *outputPath, char *teamID, char *appStoreBinary);
const char* mach_error_string(kern_return_t);
kern_return_t mach_vm_allocate(vm_map_t          target_task,                  mach_vm_address_t address,                  mach_vm_size_t    size,                  int               flags);
kern_return_t mach_vm_map(vm_map_t target_task, mach_vm_address_t *address, mach_vm_size_t size, mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset, boolean_t copy, vm_prot_t cur_protection, vm_prot_t max_protection, vm_inherit_t inheritance);
kern_return_t mach_vm_protect(mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_max, vm_prot_t new_prot);
kern_return_t mach_vm_copy(vm_map_t          target_task,              mach_vm_address_t source_address,              mach_vm_size_t    count,              mach_vm_address_t dest_address);
static int inClose = 0;

#define PT_TRACE_ME     0
#define PT_DETACH       11
#define PT_ATTACHEXC    14
int ptrace(int, pid_t, caddr_t, int);

static uint64_t THE_OFFSET;

int (*orig_daemon)(int, int);
int (*orig_fork)(void);
int (*orig_vfork)(void);
int (*orig_access)(const char *path, int amode);
int (*orig_execve)(const char* path, char* const argv[], char* const envp[]);
int (*orig_posix_spawn)(pid_t *restrict pid, const char *restrict path,
  const posix_spawn_file_actions_t *file_actions,
  const posix_spawnattr_t *restrict attrp, char *const argv[restrict],
  char *const envp[restrict]);
int (*orig_stat)(const char *restrict path, struct stat *restrict buf);
int (*orig_uname)(struct utsname *name);

// thanks @miticollo
void handle_exception(arm_thread_state64_t *state) {
    uint64_t pc = (uint64_t) __darwin_arm_thread_state64_get_pc(*state);
    __darwin_arm_thread_state64_set_pc_fptr(*state, (void *) (pc + THE_OFFSET));
    if (*(uint64_t *) pc != *(uint64_t *) __darwin_arm_thread_state64_get_pc(*state)) {
        fprintf(stderr, "pc and pc+off instruction doesn't match\n");
        kill(getpid(), SIGKILL);
    }
    printf("jump: %p -> %p\n", pc, (uint64_t) __darwin_arm_thread_state64_get_pc(*state));
}

void handleFaultyTextPage(int signum, struct siginfo_t *siginfo, void *context) {
    static int failureCount;

    printf("Got SIGBUS, fixing\n");

    struct __darwin_ucontext *ucontext = (struct __darwin_ucontext *) context;
    struct __darwin_mcontext64 *machineContext = (struct __darwin_mcontext64 *) ucontext->uc_mcontext;

    handle_exception(&machineContext->__ss);
    // handle_exception changed register state for continuation
}

#define CS_DEBUGGED 0x10000000
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int isJITEnabled() {
    int flags;
    csops(getpid(), 0, &flags, sizeof(flags));
    return (flags & CS_DEBUGGED) != 0;
}

const struct segment_command_64 *builtin_getsegbyname(struct mach_header_64 *mhp, char *segname)
{
    struct segment_command_64 *sgp;
    uint32_t i;
        
    sgp = (struct segment_command_64 *)
	      ((char *)mhp + sizeof(struct mach_header_64));
    for (i = 0; i < mhp->ncmds; i++){
        if(sgp->cmd == LC_SEGMENT_64)
            if(strncmp(sgp->segname, segname, sizeof(sgp->segname)) == 0)
                return(sgp);
            sgp = (struct segment_command_64 *)((char *)sgp + sgp->cmdsize);
    }
    return NULL;
}

size_t size_of_image(struct mach_header_64 *header) {
    struct load_command *lc = (struct load_command *) (header + 1);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        //printf("cmd %d = %d\n", i, lc->cmd);
        if (lc->cmd == LC_CODE_SIGNATURE) {
            struct linkedit_data_command *cmd = (struct linkedit_data_command *)lc;
            //printf("size %d\n", cmd->dataoff + cmd->datasize);
            return header->sizeofcmds + cmd->dataoff + cmd->datasize;
        }
        lc = (struct load_command *) ((char *) lc + lc->cmdsize);
    }
    printf("LC_CODE_SIGNATURE is not found\n");
    abort();
    return 0;
}

static void post_fork(int pid) {
    printf("fork pid=%d\n", pid);
    if (pid == 0) {
        // fix fork by any chance...
        kill(getpid(), SIGSTOP);
        usleep(2000);

        if (THE_OFFSET) return;

        kern_return_t result;
        const struct mach_header_64 *header = _dyld_get_image_header(0);
        uint64_t slide = _dyld_get_image_vmaddr_slide(0);
        size_t size = size_of_image(header);

        // SIMULATE READ ONLY
        //const struct section_64 *thisSect = getsectbyname(SEG_TEXT, SECT_TEXT);
        //result = mach_vm_protect(mach_task_self(), thisSect->addr + slide, thisSect->size, TRUE, VM_PROT_READ);
        //printf("RO mach_vm_protect: %s\n", mach_error_string(result));

        // Copy the whole image memory
        //mach_vm_address_t remap;
        const struct mach_header_64 *remap;
        result = mach_vm_map(mach_task_self(), &remap, size, 0, VM_FLAGS_ANYWHERE, NULL, NULL, FALSE, VM_PROT_READ|VM_PROT_WRITE, VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE, VM_INHERIT_DEFAULT);
        printf("line %d: %p\n", __LINE__, remap);
        result = mach_vm_copy(mach_task_self(), header, size, remap);
        printf("line %d: %s\n", __LINE__, mach_error_string(result));
        THE_OFFSET = (uint64_t)remap - (uint64_t)header;
        printf("offset=%p\n", THE_OFFSET);

        const struct segment_command_64 *seg = builtin_getsegbyname(remap, SEG_TEXT);
        mach_vm_address_t text_remap = remap + (seg->vmaddr + slide - (uint64_t)header);
        result = mach_vm_protect(mach_task_self(), text_remap, seg->vmsize, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        printf("mach_vm_protect(%p): %s\n", text_remap, mach_error_string(result));

        // Unblock signal handler
        sigset_t set;
	     sigemptyset(&set);
	     sigprocmask(SIG_SETMASK, &set, 0);

        struct sigaction sigAction;
        sigAction.sa_sigaction = handleFaultyTextPage;
        sigAction.sa_flags = SA_SIGINFO;
        sigaction(SIGBUS, &sigAction, NULL);

        if (!isJITEnabled()) {
            fprintf(stderr, "forked process couldn't get JIT, killing\n");
            kill(getpid(), SIGKILL);
        }
    } else if (pid > 0) {
        // Enable JIT for the child process
        int ret;
        ret = ptrace(PT_ATTACHEXC, pid, 0, 0);
        if (!ret && !isJITEnabled()) {
            fprintf(stderr, "%s: looks like this process does not have get-task-allow entitlement. Forkfix will abort\n", getprogname());
            abort();
        }
        if (!ret) {
            // Detach process
            for (int i = 0; i < 1000; i++) {
                usleep(1000);
                ret = ptrace(PT_DETACH, pid, 0, 0);
                if (!ret) {
                    break;
                }
            }
            printf("detach=%d\n", ret);
            kill(pid, SIGCONT);
        }
        //assert(!ret);
    }
}

int hooked_fork() {
    int pid = orig_fork();
    post_fork(pid);
    return pid;
}

int hooked_vfork() {
    int pid = orig_vfork();
    post_fork(pid);
    return pid;
}

int hooked_daemon(nochdir, noclose)
	int nochdir, noclose;
{
	struct sigaction osa, sa;
	int fd;
	pid_t newgrp;
	int oerrno;
	int osa_ok;

	/* A SIGHUP may be thrown when the parent exits below. */
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	osa_ok = sigaction(SIGHUP, &sa, &osa);
#ifndef VARIANT_PRE1050
	//move_to_root_bootstrap();
#endif /* !VARIANT_PRE1050 */
	switch (hooked_fork()) {
	case -1:
		return (-1);
	case 0:
		break;
	default:
		_exit(0);
	}

	newgrp = setsid();
	oerrno = errno;
	if (osa_ok != -1)
		sigaction(SIGHUP, &osa, NULL);

	if (newgrp == -1) {
		errno = oerrno;
		return (-1);
	}

	if (!nochdir)
		(void)chdir("/");

	if (!noclose && (fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}
	return (0);
}

bool g_sign_failed = false;

void machoEnumerateArchs(FILE* machoFile, bool (^archEnumBlock)(struct mach_header_64* header, uint32_t offset))
{
    struct mach_header_64 mh={0};
    if(fseek(machoFile,0,SEEK_SET)!=0)return;
    if(fread(&mh,sizeof(mh),1,machoFile)!=1)return;
    
    if(mh.magic==FAT_MAGIC || mh.magic==FAT_CIGAM)//and || mh.magic==FAT_MAGIC_64 || mh.magic==FAT_CIGAM_64? with fat_arch_64
    {
        struct fat_header fh={0};
        if(fseek(machoFile,0,SEEK_SET)!=0)return;
        if(fread(&fh,sizeof(fh),1,machoFile)!=1)return;
        
        for(int i = 0; i < OSSwapBigToHostInt32(fh.nfat_arch); i++)
        {
            uint32_t archMetadataOffset = sizeof(fh) + sizeof(struct fat_arch) * i;

            struct fat_arch fatArch={0};
            if(fseek(machoFile, archMetadataOffset, SEEK_SET)!=0)break;
            if(fread(&fatArch, sizeof(fatArch), 1, machoFile)!=1)break;

            if(fseek(machoFile, OSSwapBigToHostInt32(fatArch.offset), SEEK_SET)!=0)break;
            if(fread(&mh, sizeof(mh), 1, machoFile)!=1)break;

            if(mh.magic != MH_MAGIC_64 && mh.magic != MH_CIGAM_64) continue; //require Macho64
            
            if(!archEnumBlock(&mh, OSSwapBigToHostInt32(fatArch.offset)))
                break;
        }
    }
    else if(mh.magic == MH_MAGIC_64 || mh.magic == MH_CIGAM_64) //require Macho64
    {
        archEnumBlock(&mh, 0);
    }
}

void machoGetInfo(FILE* candidateFile, bool *isMachoOut, bool *isLibraryOut)
{
    if (!candidateFile) return;

    __block bool isMacho=false;
    __block bool isLibrary = false;
    
    machoEnumerateArchs(candidateFile, ^bool(struct mach_header_64* header, uint32_t offset) {
        switch(OSSwapLittleToHostInt32(header->filetype)) {
            case MH_DYLIB:
            case MH_BUNDLE:
                isLibrary = true;
            case MH_EXECUTE:
                isMacho = true;
                return false;

            default:
                return true;
        }
    });

    if (isMachoOut) *isMachoOut = isMacho;
    if (isLibraryOut) *isLibraryOut = isLibrary;
}



int execBinary(const char* path, char** argv)
{
    pid_t pid = 0;
    posix_spawn_file_actions_t file_actions;
    int ret;

    posix_spawn_file_actions_init(&file_actions);
    
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull == -1) {
        return -1;
    }

    posix_spawn_file_actions_adddup2(&file_actions, devnull, STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&file_actions, devnull, STDERR_FILENO);

    ret = posix_spawn(&pid, path, &file_actions, NULL, (char* const*)argv, NULL);

    close(devnull);

    posix_spawn_file_actions_destroy(&file_actions);

    if(ret != 0) {
        return -1;
    }

    int status = 0;
    while(waitpid(pid, &status, 0) != -1)
    {
        if (WIFSIGNALED(status)) {
            return 128 + WTERMSIG(status);
        } else if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
    };

    return -1;
}

typedef struct ProcessedFile {
    char path[PATH_MAX];
    struct ProcessedFile* next;
} ProcessedFile;

ProcessedFile* processed_files_head = NULL;

bool is_file_processed(const char* path) {
    ProcessedFile* current = processed_files_head;
    while (current) {
        if (strcmp(current->path, path) == 0) {
            return true;
        }
        current = current->next;
    }
    return false;
}

void add_processed_file(const char* path) {
    ProcessedFile* new_file = (ProcessedFile*)malloc(sizeof(ProcessedFile));
    strncpy(new_file->path, path, PATH_MAX);
    new_file->next = processed_files_head;
    processed_files_head = new_file;
}


void get_identifier(const char* path, char* identifier) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        exit(1);
    }

    pid_t pid;
    posix_spawn_file_actions_t file_actions;
    posix_spawnattr_t attr;

    posix_spawn_file_actions_init(&file_actions);
    posix_spawn_file_actions_adddup2(&file_actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_addclose(&file_actions, pipefd[0]);

    posix_spawnattr_init(&attr);

    char* const argv[] = {"/var/jb/basebins/ldid_dpkg_autosign", "-h", (char*)path, NULL};
    int status = posix_spawn(&pid, "/var/jb/basebins/ldid_dpkg_autosign", &file_actions, &attr, argv, NULL);
    if (status != 0) {
        perror("posix_spawn failed");
        exit(1);
    }

    close(pipefd[1]);

    FILE* fp = fdopen(pipefd[0], "r");
    if (fp == NULL) {
        perror("fdopen failed");
        exit(1);
    }

    char output[PATH_MAX];
    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, "Identifier=")) {
            sscanf(output, "Identifier=%s", identifier);
            break;
        }
    }

    fclose(fp);
    close(pipefd[0]);

    int status_code;
    waitpid(pid, &status_code, 0);
    if (WIFEXITED(status_code) && WEXITSTATUS(status_code) != 0) {
        fprintf(stderr, "Child process exited with error status\n");
        exit(1);
    }
}

int autosign(char* path)
{
    if (strstr(path, ".dpkg-new") == NULL && strstr(path, "/Library/dpkg/tmp.ci/") == NULL)
        return 0;
    
    if (is_file_processed(path)) {
        return 0;
    }

    FILE* fp = fopen(path, "rb");
    if(fp) {
        bool ismacho=false,islib=false;
        machoGetInfo(fp, &ismacho, &islib);
        
        if(ismacho)
        {
            if(!islib)
            {
                char identifier[PATH_MAX];
                get_identifier(path, identifier);

                if (strlen(identifier) == 0) {
                    fprintf(stderr, "Failed to retrieve identifier\n");
                    return 1;
                }

                char identifier_arg[PATH_MAX];
                snprintf(identifier_arg, sizeof(identifier_arg), "-I%s", identifier);
                
                char sent[PATH_MAX];
                
                if(strstr(path, "/jb/Applications/TweakSettings.app/TweakSettings")) {
                    snprintf(sent,sizeof(sent),"-S%s", "/var/jb/basebins/rm_ent_tweak.plist");
                } else {
                    snprintf(sent,sizeof(sent),"-S%s", "/var/jb/basebins/rm_ent.plist");
                }

                char* args[] = {"ldid_dpkg_autosign", "-M", sent, path, identifier_arg, NULL};
                int status = execBinary("/var/jb/basebins/ldid_dpkg_autosign", args);
                if(status != 0) {
                    g_sign_failed = true;
                }
            }
            
//                char* args[] = {"ct_bypass_dpkg_autosign", "-i", path, "-o", path, "-r", NULL};
                int status = apply_coretrust_bypass_wrapper(path, path, NULL, NULL);
                if(status != 0) {
                    g_sign_failed = true;
                }

        }
        
        add_processed_file(path);
        fclose(fp);
    }

    return 0;
}


int (*dpkghook_orig_close)(int fd);
int dpkghook_new_close(int fd)
{
    if (inClose == 1) {
        return dpkghook_orig_close(fd);
    }
    
        inClose = 1;
        int olderr=errno;
        
        char path[PATH_MAX]={0};
        int s=fcntl(fd, F_GETPATH, path);
        
        errno = olderr;
        
        int ret = dpkghook_orig_close(fd);
        
        olderr=errno;
        
        if(s==0 && path[0])
        {
            struct stat st={0};
            stat(path, &st);
            
            
            int autosign(char* path);
            autosign(path);
        }
        
    errno = olderr;
    inClose = 0;
    return ret;
}

//int __execve_hook(const char *path, char *const argv[], char *const envp[])
//{
//    // For execve, just make it call posix_spawn instead
//    // Since posix_spawn is hooked, all the logic will happen in there
//
//    posix_spawnattr_t attr = NULL;
//    posix_spawnattr_init(&attr);
//    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
//    int result = posix_spawn(NULL, path, NULL, &attr, argv, envp);
//    if (attr) {
//        posix_spawnattr_destroy(&attr);
//    }
//
//    if(result != 0) { // posix_spawn will return errno and restore errno if it fails
//        errno = result; // so we need to set errno by ourself
//        return -1;
//    }
//
//    return result;
//}

struct rebinding rebindings[4] = {
    {"daemon", hooked_daemon, (void *)&orig_daemon},
    {"fork", hooked_fork, (void *)&orig_fork},
    {"vfork", hooked_vfork, (void *)&orig_vfork},
    {"close", dpkghook_new_close, (void**)&dpkghook_orig_close},
};

int (*orig_strstr)(const char *__big, const char *__little);
char hooked_strstr(const char *__big, const char *__little) {
    if (strcmp(__little, "/Applications/TweakSettings.app/TweakSettings") == 0) {
        return 'a';
    }
    return orig_strstr(__big, __little);
}

struct rebinding rebindings_tweak[1] = {
    {"strstr", hooked_strstr, (void *)&orig_strstr},
};

__attribute__((constructor)) static void init(int argc, char **argv) {
    @autoreleasepool {
        NSProcessInfo *processInfo = [NSProcessInfo processInfo];
        
        NSString *currentProcessName = [processInfo processName];
        
        if ([currentProcessName isEqualToString:@"zsh"] || [currentProcessName isEqualToString:@"dash"] || [currentProcessName isEqualToString:@"apt-config"] || [currentProcessName isEqualToString:@"gpgv"]) {
            pid_t pid = [[NSProcessInfo processInfo] processIdentifier];
            char pathBuffer[PROC_PIDPATHINFO_MAXSIZE];
            proc_pidpath(pid, pathBuffer, sizeof(pathBuffer));
            
            if (strstr(pathBuffer, "/jb/usr/bin/zsh")) {
                execve("/var/jb/basebins/zsh", argv, environ);
            } else if (strstr(pathBuffer, "/jb/usr/bin/dash")) {
                execve("/var/jb/basebins/dash", argv, environ);
            } else if (strstr(pathBuffer, "/jb/usr/bin/apt-config")) {
                execve("/var/jb/basebins/apt-config", argv, environ);
            } else if (strstr(pathBuffer, "/jb/usr/bin/gpgv")) {
                execve("/var/jb/basebins/gpgv", argv, environ);
            }
        } else {
            if ([currentProcessName isEqualToString:@"dpkg"]) {
                rebind_symbols(rebindings, 4);
            } else {
                rebind_symbols(rebindings, 3);
            }
        }
        
        if ([currentProcessName isEqualToString:@"sudo"] || [currentProcessName isEqualToString:@"su"] || [currentProcessName isEqualToString:@"passwd"] || [currentProcessName isEqualToString:@"login"] || [currentProcessName isEqualToString:@"tweaksettings-utility"]) {
            
            if ([currentProcessName isEqualToString:@"tweaksettings-utility"]) {
                rebind_symbols(rebindings_tweak, 1);
            }
            
            if (getuid() == 501) {
                execve("/var/jb/basebins/sudo_spawn_root", argv, environ);
            }
            
            const char *suid_fix = getenv("SUID_FIX");
            
            if (suid_fix && strcmp(suid_fix, "1") == 0) {
                setregid(501, 0);
                setreuid(501, 0);
                unsetenv("SUID_FIX");
            }
        }
    }
}
