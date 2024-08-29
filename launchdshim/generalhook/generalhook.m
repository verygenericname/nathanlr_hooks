#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
//#include <substrate.h>
//#include <libhooker/libhooker.h>
#include <spawn.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <utils.h>
#include <litehook.h>
#include "sandbox.h"

#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA

@interface NSBundle(private)
- (id)_cfBundle;
@end

void* _CTServerConnectionCreate(CFAllocatorRef, void *, void *);

int64_t _CTServerConnectionSetCellularUsagePolicy(CFTypeRef* ct, NSString* identifier, NSDictionary* policies);

void chineseWifiFixup(void)
{
    _CTServerConnectionSetCellularUsagePolicy(
        _CTServerConnectionCreate(kCFAllocatorDefault, NULL, NULL),
        NSBundle.mainBundle.bundleIdentifier,
        @{
            @"kCTCellularDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow",
            @"kCTWiFiDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow"
        }
    );
}

int csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int ptrace(int, int, int, int);

BOOL isJITEnabled()
{
    int flags;
    csops(getpid(), 0, &flags, sizeof(flags));
    return (flags & CS_DEBUGGED) != 0;
}

int csops_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize)
{
    int rv = syscall(SYSCALL_CSOPS, pid, ops, useraddr, usersize);
    if (rv != 0) return rv;
    if (ops == 0) {
        *((uint32_t *)useraddr) |= 0x4000000;
    }
    return rv;
}

int csops_audittoken_hook(pid_t pid, unsigned int ops, void *useraddr, size_t usersize, audit_token_t *token)
{
    int rv = syscall(SYSCALL_CSOPS_AUDITTOKEN, pid, ops, useraddr, usersize, token);
    if (rv != 0) return rv;
    if (ops == 0) {
        *((uint32_t *)useraddr) |= 0x4000000;
    }
    return rv;
}

extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern XPC_RETURNS_RETAINED xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);

bool jitterdSystemWideIsReachable(void)
{
    int sbc = sandbox_check(getpid(), "mach-lookup", SANDBOX_FILTER_GLOBAL_NAME | SANDBOX_CHECK_NO_REPORT, "com.hrtowii.jitterd.systemwide");
    return sbc == 0;
}

mach_port_t jitterdSystemWideMachPort(void)
{
    mach_port_t outPort = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS;

    if (getpid() == 1) {
        mach_port_t self_host = mach_host_self();
        kr = host_get_special_port(self_host, HOST_LOCAL_NODE, 16, &outPort);
        mach_port_deallocate(mach_task_self(), self_host);
    }
    else {
        kr = bootstrap_look_up(bootstrap_port, "com.hrtowii.jitterd.systemwide", &outPort);
    }

    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    return outPort;
}

xpc_object_t sendjitterdMessageSystemWide(xpc_object_t xdict)
{
    xpc_object_t jitterd_xreply = NULL;
    if (jitterdSystemWideIsReachable()) {
        mach_port_t jitterdPort = jitterdSystemWideMachPort();
        if (jitterdPort != -1) {
            xpc_object_t pipe = xpc_pipe_create_from_port(jitterdPort, 0);
            if (pipe) {
                int err = xpc_pipe_routine(pipe, xdict, &jitterd_xreply);
                if (err != 0) jitterd_xreply = NULL;
                xpc_release(pipe);
            }
            mach_port_deallocate(mach_task_self(), jitterdPort);
        }
    }
    return jitterd_xreply;
}

#define JBD_MSG_PROC_SET_DEBUGGED 23
int64_t jitterd(pid_t pid)
{
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_int64(message, "id", JBD_MSG_PROC_SET_DEBUGGED);
    xpc_dictionary_set_int64(message, "pid", pid);
    xpc_object_t reply = sendjitterdMessageSystemWide(message);
    int64_t result = -1;
    if (reply) {
        result  = xpc_dictionary_get_int64(reply, "result");
        xpc_release(reply);
    }
    return result;
}

static void overwriteMainCFBundle() {
    // Overwrite CFBundleGetMainBundle
    uint32_t *pc = (uint32_t *)CFBundleGetMainBundle;
    void **mainBundleAddr = 0;
    while (true) {
        uint64_t addr = aarch64_get_tbnz_jump_address(*pc, (uint64_t)pc);
        if (addr) {
            // adrp <- pc-1
            // tbnz <- pc
            // ...
            // ldr  <- addr
            mainBundleAddr = (void **)aarch64_emulate_adrp_ldr(*(pc-1), *(uint32_t *)addr, (uint64_t)(pc-1));
            break;
        }
        ++pc;
    }
    assert(mainBundleAddr != NULL);
    *mainBundleAddr = (__bridge void *)NSBundle.mainBundle._cfBundle;
}

static void overwriteMainNSBundle(NSBundle *newBundle) {
    // Overwrite NSBundle.mainBundle
    // iOS 16: x19 is _MergedGlobals
    // iOS 17: x19 is _MergedGlobals+4

    NSString *oldPath = NSBundle.mainBundle.executablePath;
    uint32_t *mainBundleImpl = (uint32_t *)method_getImplementation(class_getClassMethod(NSBundle.class, @selector(mainBundle)));
    for (int i = 0; i < 20; i++) {
        void **_MergedGlobals = (void **)aarch64_emulate_adrp_add(mainBundleImpl[i], mainBundleImpl[i+1], (uint64_t)&mainBundleImpl[i]);
        if (!_MergedGlobals) continue;

        // In iOS 17, adrp+add gives _MergedGlobals+4, so it uses ldur instruction instead of ldr
        if ((mainBundleImpl[i+4] & 0xFF000000) == 0xF8000000) {
            uint64_t ptr = (uint64_t)_MergedGlobals - 4;
            _MergedGlobals = (void **)ptr;
        }

        for (int mgIdx = 0; mgIdx < 20; mgIdx++) {
            if (_MergedGlobals[mgIdx] == (__bridge void *)NSBundle.mainBundle) {
                _MergedGlobals[mgIdx] = (__bridge void *)newBundle;
                break;
            }
        }
    }

    assert(![NSBundle.mainBundle.executablePath isEqualToString:oldPath]);
}

int envbuf_find(const char *envp[], const char *name)
{
    if (envp) {
        unsigned long nameLen = strlen(name);
        int k = 0;
        const char *env = envp[k++];
        while (env != NULL) {
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
    while (env != NULL) {
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

void remove_substring(char *str, const char *sub) {
    char *match;
    size_t len_sub = strlen(sub);
    
    // Search for the substring in the string
    while ((match = strstr(str, sub)) != NULL) {
        // Move the part of the string after the substring to the beginning
        memmove(match, match + len_sub, strlen(match + len_sub) + 1);
    }
}

int (*orig_posix_spawn)(pid_t * __restrict pid, const char * __restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t * __restrict attrp,
                        char *const argv[ __restrict], char *const envp[ __restrict]);

int hooked_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    if (argv != NULL && argv[2] != NULL) {
        if (strstr(argv[2], "tweaksettings-utility") != NULL) {
            path = "/var/jb/usr/bin/tweaksettings-utility";
            argv[0] = (char *)path;
            char **envc = envbuf_mutcopy((const char **)envp);
            envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", "/var/jb/usr/lib/libTS2JailbreakEnv.dylib");
            remove_substring(argv[2], "/var/jb/usr/bin/tweaksettings-utility ");
            argv[1] = argv[2];
            int ret = orig_posix_spawn(pid, path, file_actions, attrp, argv, envc);
            envbuf_free(envc);
            return ret;
        }
    }
    return orig_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}

char *JB_SandboxExtensions = NULL;

void unsandbox(void) {
    char extensionsCopy[strlen(JB_SandboxExtensions)];
    strcpy(extensionsCopy, JB_SandboxExtensions);
    char *extensionToken = strtok(extensionsCopy, "|");
    while (extensionToken != NULL) {
        sandbox_extension_consume(extensionToken);
        extensionToken = strtok(NULL, "|");
    }
}

typedef struct __SecTask * SecTaskRef;
extern CFTypeRef SecTaskCopyValueForEntitlement(
        SecTaskRef task,
        NSString* entitlement,
        CFErrorRef  _Nullable *error
    )
    __attribute__((weak_import));

extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef allocator)
    __attribute__((weak_import));

BOOL getEntitlementValue(NSString *key)
{
    if (SecTaskCreateFromSelf == NULL || SecTaskCopyValueForEntitlement == NULL)
        return NO;
    SecTaskRef sec_task = SecTaskCreateFromSelf(NULL);
    if(!sec_task) return NO;
    CFTypeRef value = SecTaskCopyValueForEntitlement(sec_task, key, nil);
    if (value != nil)
    {
        CFRelease(value);
    }
    CFRelease(sec_task);
    return value != nil && [(__bridge id)value boolValue];
}

char *getSandboxExtensionsFromPlist() {
    NSString *filePath = @"/System/Library/VideoCodecs/NLR_SANDBOX_EXTENSIONS.plist";
    
    NSDictionary *plistDict = [NSDictionary dictionaryWithContentsOfFile:filePath];
    
    NSString *sandboxExtensions = plistDict[@"NLR_SANDBOX_EXTENSIONS"];
    
    if (sandboxExtensions) {
        return strdup([sandboxExtensions UTF8String]);
    } else {
        return NULL;
    }
}

uint64_t (*orig_LSFindBundleWithInfo_NoIOFiltered)(id, uint64_t, CFStringRef, Boolean, CFURLRef, UInt64, NSString *, BOOL (^)(id, uint64_t, const id), NSError **);

uint64_t new_LSFindBundleWithInfo_NoIOFiltered(id arg1, uint64_t arg2, CFStringRef arg3, Boolean arg4, CFURLRef arg5, UInt64 arg6, NSString *arg7, BOOL (^arg8)(id, uint64_t, const id), NSError **arg9) {
    
    CFURLRef newUrl = NULL;

    if (arg5 != NULL) {
        NSString *cfURLString = (__bridge NSString *)CFURLCopyPath(arg5);
        NSString *strippedLast = [cfURLString stringByDeletingLastPathComponent];
        NSString *appName = [cfURLString lastPathComponent];
        
        if ([strippedLast isEqualToString:@"/System/Library/VideoCodecs/Applications"]) {
            NSString *baseURLString = @"/Applications/";
            NSString *appendURLString = [baseURLString stringByAppendingString:appName];
            
            newUrl = CFURLCreateWithString(kCFAllocatorDefault, (__bridge CFStringRef)appendURLString, NULL);
        } else if ([strippedLast isEqualToString:@"/System/Library/VideoCodecs/CoreServices"]) {
            NSString *baseURLString = @"/System/Library/CoreServices/";
            NSString *appendURLString = [baseURLString stringByAppendingString:appName];
            
            newUrl = CFURLCreateWithString(kCFAllocatorDefault, (__bridge CFStringRef)appendURLString, NULL);
        }
    }

    uint64_t ret = orig_LSFindBundleWithInfo_NoIOFiltered(arg1, arg2, arg3, arg4, newUrl, arg6, arg7, arg8, arg9);

    if (newUrl) {
        CFRelease(newUrl);
    }

    return ret;
}

int (*orig_setuid)(uid_t uid);
int (*orig_setgid)(gid_t gid);

int hooked_setuid(uid_t uid) {
    return 0;
}

int hooked_setgid(gid_t gid) {
    return 0;
}

int enableJIT(pid_t pid)
{
    for (int retries = 0; retries < 100; retries++)
    {
        jitterd(pid);
//            NSLog(@"Hopefully enabled jit");
        if (isJITEnabled())
        {
//                NSLog(@"[+] JIT has heen enabled with PT_TRACE_ME");
            return 0;
        }
        usleep(10000);
    }
    return 1;
}

@class MIContainer;
@interface MIContainer : NSObject <NSCopying>
- (BOOL)makeContainerLiveReplacingContainer:(id)arg1 reason:(unsigned long long)arg2 waitForDeletion:(BOOL)arg3 withError:(id*)arg4;
- (NSURL *)containerURL;
@end

static BOOL isNewContainer = NO;

NSString *getBundlePathFromExecutablePath(const char *executablePath) {
    NSString *executablePathStr = [NSString stringWithUTF8String:executablePath];
    
    if (strncmp(executablePath, "/System/Library/VideoCodecs/Applications/", 41) == 0) {
        NSString *relativePath = [executablePathStr substringFromIndex:[@"/System/Library/VideoCodecs/Applications/" length]];
        NSString *bundlePath = [@"/Applications/" stringByAppendingPathComponent:relativePath];
        
        NSString *directoryPath = [bundlePath stringByDeletingLastPathComponent];
        return directoryPath;
    }
    
    return nil;
}


NSString* findAppNameInBundlePath(NSString* bundlePath)
{
    NSArray* bundleItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundlePath error:nil];
    for(NSString* bundleItem in bundleItems)
    {
        if([bundleItem.pathExtension isEqualToString:@"app"])
        {
            NSString *fullPath = [@"/" stringByAppendingString:bundleItem];
            return fullPath;
        }
    }
    return nil;
}

NSString* findAppNameInBundlePath2(NSString* bundlePath)
{
    NSArray* bundleItems = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:bundlePath error:nil];
    for(NSString* bundleItem in bundleItems)
    {
        if([bundleItem.pathExtension isEqualToString:@"app"])
        {
            NSString* appName = [bundleItem stringByDeletingPathExtension];
            return appName;
        }
    }
    return nil;
}

BOOL fileExists(NSString *filePath) {
    NSFileManager *fileManager = [NSFileManager defaultManager];
    return [fileManager fileExistsAtPath:filePath];
}

BOOL removeFileAtPath(NSString *filePath) {
    NSFileManager *fileManager = [NSFileManager defaultManager];

    NSError *error;
        if ([fileManager removeItemAtPath:filePath error:&error]) {
            return YES;
        } else {
    //
        }

    return NO;
}

BOOL (*orig_makeContainerLiveReplacingContainer)(MIContainer* self, SEL _cmd, id arg1, unsigned long long arg2, BOOL arg3, id* arg4);
BOOL new_makeContainerLiveReplacingContainer(MIContainer* self, SEL _cmd, id arg1, unsigned long long arg2, BOOL arg3, id* arg4) {
    BOOL result = orig_makeContainerLiveReplacingContainer(self, _cmd, arg1, arg2, arg3, arg4);

    if (result && arg2 == 2) {
        isNewContainer = YES;
    } else {
        isNewContainer = NO;
    }

    if (isNewContainer) {
        NSURL *containerURL = [self containerURL];
        NSString *AppPath = findAppNameInBundlePath([containerURL path]);
        NSString *AppPathApp = [[containerURL path] stringByAppendingString:AppPath];
        NSString *appName = findAppNameInBundlePath2([containerURL path]);
        if(fileExists([AppPathApp stringByAppendingString:@"/appstorehelper.dylib"])) {
            removeFileAtPath([AppPathApp stringByAppendingString:@"/appstorehelper.dylib"]);
            removeFileAtPath([NSString stringWithFormat:@"%@/%@", AppPathApp, [appName stringByAppendingString:@"_NATHANLR"]]);
        }
    }

    return result;
}

char *execPath;

static BOOL (*orig_isLoaded)(NSBundle *self, SEL _cmd);

BOOL hook_isLoaded(NSBundle *self, SEL _cmd) {
    NSString *targetBundlePath = getBundlePathFromExecutablePath(execPath);

    if ([[self bundlePath] isEqualToString:targetBundlePath]) {
        return YES;
    }

    return orig_isLoaded(self, _cmd);
}

__attribute__((constructor)) static void init(int argc, char **argv, char *envp[]) {
    @autoreleasepool {
        if (!getEntitlementValue(@"com.apple.private.security.no-container")
            || !getEntitlementValue(@"com.apple.private.security.no-sandbox"))
        {
            JB_SandboxExtensions = getSandboxExtensionsFromPlist();
            if (JB_SandboxExtensions) {
                unsandbox();
                free(JB_SandboxExtensions);
            }
        }
        
        if (enableJIT(getpid()) != 0) {
            //            NSLog(@"[-] Failed to enable JIT");
            exit(1);
        }
        
        unsetenv("DYLD_INSERT_LIBRARIES");
        
        litehook_hook_function(csops, csops_hook);
        litehook_hook_function(csops_audittoken, csops_audittoken_hook);
        //        init_bypassDyldLibValidation();
        
        NSString *bundlePath = getBundlePathFromExecutablePath(argv[0]);
        
        if (bundlePath != nil) {
            NSBundle *appBundle = [[NSBundle alloc] initWithPath:bundlePath];
            Class bundleClass = objc_getClass("NSBundle");
            
            overwriteMainNSBundle(appBundle);
            overwriteMainCFBundle();
            
            NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
            objcArgv[0] = appBundle.executablePath;
            [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
            execPath = argv[0];
            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
            typedef void (*MSHookMessageEx_t)(Class, SEL, IMP, IMP *);
            MSHookMessageEx_t MSHookMessageEx = (MSHookMessageEx_t)dlsym(substrateHandle, "MSHookMessageEx");
            MSHookMessageEx(objc_getClass("NSBundle"), @selector(isLoaded), (IMP)hook_isLoaded, (IMP *)&orig_isLoaded);
            //            NSProcessInfo.processInfo.processName = appBundle.infoDictionary[@"CFBundleExecutable"];
            //            *_CFGetProgname() = NSProcessInfo.processInfo.processName.UTF8String;
        } else if (strstr(argv[0], "/jb/Applications/TweakSettings.app/") != NULL || (strstr(argv[0], "/jb/Applications/iCleaner.app/") != NULL)) {
            chineseWifiFixup();
            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
            typedef void (*MSHookFunction_t)(void *, void *, void **);
            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            if (strstr(argv[0], "/jb/Applications/iCleaner.app/") != NULL) {
                MSHookFunction(setuid, (void*)hooked_setuid, (void**)&orig_setuid);
                MSHookFunction(setgid, (void*)hooked_setgid, (void**)&orig_setgid);
            } else {
                MSHookFunction(posix_spawn, (void*)hooked_posix_spawn, (void**)&orig_posix_spawn);
            }
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/CoreTelephony.framework/Support/CommCenter") == 0) {
            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
            typedef void* MSImageRef;
            typedef void* (*MSGetImageByName_t)(const char *image_name);
            typedef void* (*MSFindSymbol_t)(void *image, const char *name);

            MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
            MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
            typedef void (*MSHookFunction_t)(void *, void *, void **);
            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
            uint64_t* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
            MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/SocialLayer.framework/sociallayerd.app/sociallayerd") == 0) {
            NSBundle *appBundle = [[NSBundle alloc] initWithPath:@"/System/Library/PrivateFrameworks/SocialLayer.framework/sociallayerd.app"];
            Class bundleClass = objc_getClass("NSBundle");
            
            overwriteMainNSBundle(appBundle);
            overwriteMainCFBundle();
            
            NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
            objcArgv[0] = appBundle.executablePath;
            [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
            
            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
            typedef void* MSImageRef;
            typedef void* (*MSGetImageByName_t)(const char *image_name);
            typedef void* (*MSFindSymbol_t)(void *image, const char *name);
            
            MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
            MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
            typedef void (*MSHookFunction_t)(void *, void *, void **);
            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
            uint64_t* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
            MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/installd") == 0) {
            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
            typedef void (*MSHookMessageEx_t)(Class, SEL, IMP, IMP *);
            MSHookMessageEx_t MSHookMessageEx = (MSHookMessageEx_t)dlsym(substrateHandle, "MSHookMessageEx");
            
            Class class_MIContainer = objc_getClass("MIContainer");
            MSHookMessageEx(
                            class_MIContainer,
                            @selector(makeContainerLiveReplacingContainer:reason:waitForDeletion:withError:),
                            (IMP)&new_makeContainerLiveReplacingContainer,
                            (IMP*)&orig_makeContainerLiveReplacingContainer
                            );
        } /*else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/CoreSuggestions.framework/suggestd") == 0) {
           void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
           typedef void* MSImageRef;
           typedef void* (*MSGetImageByName_t)(const char *image_name);
           typedef void* (*MSFindSymbol_t)(void *image, const char *name);
           
           MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
           MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
           typedef void (*MSHookFunction_t)(void *, void *, void **);
           MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
           
           MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
           uint64_t* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
           MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
           }*/
        
        dlopen("/var/jb/usr/lib/TweakInject.dylib", RTLD_NOW | RTLD_GLOBAL);
    }
}
