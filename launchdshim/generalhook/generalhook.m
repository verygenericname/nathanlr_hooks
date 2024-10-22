#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <substrate.h>
//#include <libhooker/libhooker.h>
#include <spawn.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <utils.h>
#import <IOKit/IOKitLib.h>
//#include <litehook.h>

#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA
#define SYSCALL_FCNTL 0x5C

char jbPath[PATH_MAX];

@interface NSBundle(private)
- (id)_cfBundle;
@end

typedef void (*CTServerConnectionSetCellularUsagePolicy_t)(CFTypeRef* ct, NSString* identifier, NSDictionary* policies);
typedef void *(*CTServerConnectionCreate_t)(CFAllocatorRef, void *, void *);

int get_boot_manifest_hash(char hash[97])
{
  const UInt8 *bytes;
  CFIndex length;
  io_registry_entry_t chosen = IORegistryEntryFromPath(0, "IODeviceTree:/chosen");
  if (!MACH_PORT_VALID(chosen)) return 1;
  CFDataRef manifestHash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
  IOObjectRelease(chosen);
  if (manifestHash == NULL || CFGetTypeID(manifestHash) != CFDataGetTypeID())
  {
    if (manifestHash) CFRelease(manifestHash);
    return 1;
  }
  length = CFDataGetLength(manifestHash);
  bytes = CFDataGetBytePtr(manifestHash);
  for (int i = 0; i < length; i++)
  {
    snprintf(&hash[i * 2], 3, "%02X", bytes[i]);
  }
  CFRelease(manifestHash);
  return 0;
}

char* return_boot_manifest_hash_main(void) {
  static char hash[97];
  int ret = get_boot_manifest_hash(hash);
  if (ret != 0) {
    fprintf(stderr, "could not get boot manifest hash\n");
    return "";
  }
    static char result[115];
    sprintf(result, "/private/preboot/%s", hash);
    return result;
}


void chineseWifiFixup(void)
{
    void *coreTelephonyFramework = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    CTServerConnectionSetCellularUsagePolicy_t _CTServerConnectionSetCellularUsagePolicy =
        (CTServerConnectionSetCellularUsagePolicy_t)dlsym(coreTelephonyFramework, "_CTServerConnectionSetCellularUsagePolicy");
    CTServerConnectionCreate_t _CTServerConnectionCreate =
        (CTServerConnectionCreate_t)dlsym(coreTelephonyFramework, "_CTServerConnectionCreate");
    
    _CTServerConnectionSetCellularUsagePolicy(
        _CTServerConnectionCreate(kCFAllocatorDefault, NULL, NULL),
        NSBundle.mainBundle.bundleIdentifier,
        @{
            @"kCTCellularDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow",
            @"kCTWiFiDataUsagePolicy" : @"kCTCellularDataUsagePolicyAlwaysAllow"
        }
    );
    dlclose(coreTelephonyFramework);
}

int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);
int csops_audittoken(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize, audit_token_t * token);
int ptrace(int, int, int, int);
int64_t sandbox_extension_consume(const char *extension_token);

@interface XBSnapshotContainerIdentity : NSObject <NSCopying>
@property (nonatomic, readonly, copy) NSString* bundleIdentifier;
- (NSString*)snapshotContainerPath;
@end

@class XBSnapshotContainerIdentity;
@class FBSSignatureValidationService;
static NSString * (*orig_XBSnapshotContainerIdentity_snapshotContainerPath)(XBSnapshotContainerIdentity*, SEL);
static NSUInteger * (*orig_trustStateForApplication)(FBSSignatureValidationService*, SEL);

//BOOL isJITEnabled()
//{
//    int flags;
//    csops(getpid(), 0, &flags, sizeof(flags));
//    return (flags & CS_DEBUGGED) != 0;
//}

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

int64_t jitterd(pid_t pid)
{
    int64_t result = 0;
    xpc_object_t message = xpc_dictionary_create_empty();
    xpc_dictionary_set_int64(message, "pid", pid);
    
    xpc_object_t jitterd_xreply = NULL;
    mach_port_t jitterdPort = MACH_PORT_NULL;
    kern_return_t kr = bootstrap_look_up(bootstrap_port, "com.hrtowii.jitterd", &jitterdPort);
    
//    if (kr != KERN_SUCCESS) return -1;
    
    xpc_object_t pipe = xpc_pipe_create_from_port(jitterdPort, 0);
    if (pipe) {
        int err = xpc_pipe_routine(pipe, message, &jitterd_xreply);
        if (err != 0) jitterd_xreply = NULL;
        xpc_release(pipe);
    }
    
    mach_port_deallocate(mach_task_self(), jitterdPort);
    
    xpc_release(message);
    
    if (jitterd_xreply) {
        result = xpc_dictionary_get_int64(jitterd_xreply, "result");
        xpc_release(jitterd_xreply);
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
    assert(mainBundleAddr);
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

void remove_substring(char *str, const char *sub) {
    char *match;
    size_t len_sub = strlen(sub);
    
    // Search for the substring in the string
    while ((match = strstr(str, sub))) {
        // Move the part of the string after the substring to the beginning
        memmove(match, match + len_sub, strlen(match + len_sub) + 1);
    }
}

int (*orig_posix_spawn)(pid_t * __restrict pid, const char * __restrict path,
                        const posix_spawn_file_actions_t *file_actions,
                        const posix_spawnattr_t * __restrict attrp,
                        char *const argv[ __restrict], char *const envp[ __restrict]);

int hooked_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char *argv[], char *const envp[]) {
    if (argv && argv[2]) {
        if (strstr(argv[2], "tweaksettings-utility")) {
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

void unsandbox() {
    FILE *file = fopen("/System/Library/VideoCodecs/tmp/NLR_SANDBOX_EXTENSIONS", "r");

    char content[763];
    fread(content, 1, 762, file);
    fclose(file);
    
    char *extensionToken = strtok(content, "|");
    while (extensionToken) {
        sandbox_extension_consume(extensionToken);
        extensionToken = strtok(NULL, "|");
    }
}

uint64_t (*orig_LSFindBundleWithInfo_NoIOFiltered)(id, uint64_t, CFStringRef, Boolean, CFURLRef, UInt64, NSString *, BOOL (^)(id, uint64_t, const id), NSError **);

uint64_t new_LSFindBundleWithInfo_NoIOFiltered(id arg1, uint64_t arg2, CFStringRef arg3, Boolean arg4, CFURLRef arg5, UInt64 arg6, NSString *arg7, BOOL (^arg8)(id, uint64_t, const id), NSError **arg9) {
    
    CFURLRef newUrl = NULL;

    if (arg5) {
        NSString *cfURLString = (__bridge NSString *)CFURLCopyPath(arg5);
        NSString *appName = [cfURLString lastPathComponent];
        
        if ((strcmp(cfURLString.UTF8String, "/System/Library/VideoCodecs/Applications/MobileSafari.app/") == 0) ||
            (strcmp(cfURLString.UTF8String, "/System/Library/VideoCodecs/Applications/Preferences.app/") == 0)) {
            newUrl = CFURLCreateWithString(kCFAllocatorDefault, (__bridge CFStringRef)[@"/Applications/" stringByAppendingString:appName], NULL);
        } /*else if ([strippedLast isEqualToString:@"/System/Library/VideoCodecs/CoreServices"]) {
            
            newUrl = CFURLCreateWithString(kCFAllocatorDefault, (__bridge CFStringRef)[@"/System/Library/CoreServices/" stringByAppendingString:appName], NULL);
        }*/
    }

    uint64_t ret = orig_LSFindBundleWithInfo_NoIOFiltered(arg1, arg2, arg3, arg4, newUrl, arg6, arg7, arg8, arg9);

    if (newUrl) {
        CFRelease(newUrl);
    }

    return ret;
}

int hooked_setuid(uid_t uid) {
    return 0;
}

int hooked_setgid(gid_t gid) {
    return 0;
}

int enableJIT(pid_t pid)
{
    for (int retries = 0; retries < 50; retries++)
    {
        if (!jitterd(pid))
        {
            return true;
        }
        usleep(10000);
    }
    return false;
}

@class MIContainer;
@interface MIContainer : NSObject <NSCopying>
- (BOOL)makeContainerLiveReplacingContainer:(id)arg1 reason:(unsigned long long)arg2 waitForDeletion:(BOOL)arg3 withError:(id*)arg4;
- (NSURL *)containerURL;
@end

NSString *getBundlePathFromExecutablePath(const char *executablePath) {
    NSString *executablePathStr = [NSString stringWithUTF8String:executablePath];
    
    if (strstr(executablePath, "/System/Library/VideoCodecs/Applications/")) {
        NSString *relativePath = [executablePathStr substringFromIndex:[@"/System/Library/VideoCodecs/Applications/" length]];
        NSString *bundlePath = [@"/Applications/" stringByAppendingPathComponent:relativePath];
        
        NSString *directoryPath = [bundlePath stringByDeletingLastPathComponent];
        return directoryPath;
    } else if ((strstr(executablePath, "/System/Library/VideoCodecs/CoreServices/SpringBoard.app/")) ||
               (strstr(executablePath, "/System/Library/VideoCodecs/CoreServices/CarPlay.app/"))) {
        NSString *relativePath = [executablePathStr substringFromIndex:[@"/System/Library/VideoCodecs/CoreServices/" length]];
        NSString *bundlePath = [@"/System/Library/CoreServices/" stringByAppendingPathComponent:relativePath];
        
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

BOOL isNewContainer = NO;

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

    if (strcmp([self bundlePath].UTF8String, targetBundlePath.UTF8String) == 0) {
        return YES;
    }

    return orig_isLoaded(self, _cmd);
}

int fcntl_hook(int fildes, int cmd, ...) {
    if (cmd == F_SETPROTECTIONCLASS) {
        char filePath[PATH_MAX];
        if (fcntl(fildes, F_GETPATH, filePath) != -1) {
            // Skip setting protection class on jailbreak apps, this doesn't work and causes snapshots to not be saved correctly
            if (strstr(filePath, "/jb/var/mobile/Library/SplashBoard/Snapshots")) {
                return 0;
            }
        }
    }

    va_list a;
    va_start(a, cmd);
    const char *arg1 = va_arg(a, void *);
    const void *arg2 = va_arg(a, void *);
    const void *arg3 = va_arg(a, void *);
    const void *arg4 = va_arg(a, void *);
    const void *arg5 = va_arg(a, void *);
    const void *arg6 = va_arg(a, void *);
    const void *arg7 = va_arg(a, void *);
    const void *arg8 = va_arg(a, void *);
    const void *arg9 = va_arg(a, void *);
    const void *arg10 = va_arg(a, void *);
    va_end(a);
    return syscall(SYSCALL_FCNTL, fildes, cmd, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9, arg10);
}

int new_XBValidateStoryboard() {
    return 0;
}

static NSString * XBSnapshotContainer_Identity_snapshotContainerPath(XBSnapshotContainerIdentity* self, SEL _cmd) {
    NSString* path = orig_XBSnapshotContainerIdentity_snapshotContainerPath(self, _cmd);
    if([path hasPrefix:@"/var/mobile/Library/SplashBoard/Snapshots/"] && ![self.bundleIdentifier hasPrefix:@"com.apple."]) {
        path = [[NSString stringWithUTF8String:jbPath] stringByAppendingPathComponent:path];
    }
    return path;
}

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
    if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] || [plistPath hasPrefix:@"/var/db"] || [plistPath hasPrefix:@"/var/jb"]) return NO;

    NSString *plistName = plistPath.lastPathComponent;

    if ([plistName hasPrefix:@"com.apple."] || [plistName hasPrefix:@"systemgroup.com.apple."] || [plistName hasPrefix:@"group.com.apple."]) return NO;

    static NSArray *additionalSystemPlistNames = @[
        @".GlobalPreferences.plist",
        @".GlobalPreferences_m.plist",
        @"bluetoothaudiod.plist",
        @"NetworkInterfaces.plist",
        @"OSThermalStatus.plist",
        @"preferences.plist",
        @"osanalyticshelper.plist",
        @"UserEventAgent.plist",
        @"wifid.plist",
        @"dprivacyd.plist",
        @"silhouette.plist",
        @"nfcd.plist",
        @"kNPProgressTrackerDomain.plist",
        @"siriknowledged.plist",
        @"UITextInputContextIdentifiers.plist",
        @"mobile_storage_proxy.plist",
        @"splashboardd.plist",
        @"mobile_installation_proxy.plist",
        @"languageassetd.plist",
        @"ptpcamerad.plist",
        @"com.google.gmp.measurement.monitor.plist",
        @"com.google.gmp.measurement.plist",
    ];

    return ![additionalSystemPlistNames containsObject:plistName];
}

bool (*orig_CFPrefsGetPathForTriplet)(CFStringRef, CFStringRef, bool, CFStringRef, char*);
bool new_CFPrefsGetPathForTriplet(CFStringRef bundleIdentifier, CFStringRef user, bool byHost, CFStringRef path, char *buffer) {
    bool orig = orig_CFPrefsGetPathForTriplet(bundleIdentifier, user, byHost, path, buffer);
    if(orig && buffer && !access("/var/jb", F_OK))
    {
        NSString* origPath = [NSString stringWithUTF8String:(char*)buffer];
        BOOL needsRedirection = preferencePlistNeedsRedirection(origPath);
        if (needsRedirection) {
            //NSLog(@"Plist redirected to /var/jb: %@", origPath);
            strcpy((char*)buffer, "/var/jb");
            strcat((char*)buffer, origPath.UTF8String);
        }
    }

    return orig;
}


__attribute__((constructor)) static void init(int argc, char **argv, char *envp[]) {
    @autoreleasepool {
        unsandbox();
        
        if (!enableJIT(getpid())) {
//            NSLog(@"[-] Failed to enable JIT");
            exit(1);
        }
        
        unsetenv("DYLD_INSERT_LIBRARIES");
        
//        litehook_hook_function(csops, csops_hook);
//        litehook_hook_function(csops_audittoken, csops_audittoken_hook);
        MSHookFunction(csops, (void*)csops_hook, 0);
        MSHookFunction(csops_audittoken, (void*)csops_audittoken_hook, 0);
        
        // init_bypassDyldLibValidation();
        
        NSString *bundlePath = getBundlePathFromExecutablePath(argv[0]);
        
        if (bundlePath != nil) {
            NSBundle *appBundle = [[NSBundle alloc] initWithPath:bundlePath];
//            Class bundleClass = objc_getClass("NSBundle");
            
            overwriteMainNSBundle(appBundle);
            overwriteMainCFBundle();
            
            NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
            objcArgv[0] = appBundle.executablePath;
            [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
            execPath = argv[0];

            MSHookMessageEx(objc_getClass("NSBundle"), @selector(isLoaded), (IMP)hook_isLoaded, (IMP *)&orig_isLoaded);
            if ((strcmp(argv[0], "/System/Library/VideoCodecs/CoreServices/SpringBoard.app/SpringBoard")) == 0) {
                char *boot_hash = return_boot_manifest_hash_main();
                snprintf(jbPath, sizeof(jbPath), "%s/jb/", boot_hash);
//                litehook_hook_function(fcntl, fcntl_hook);
                MSHookFunction(fcntl, (void*)fcntl_hook, 0);
//                typedef void* MSImageRef;
//                typedef void (*MSHookFunction_t)(void *, void *, void **);
//                MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
//                typedef void* (*MSGetImageByName_t)(const char *image_name);
//                typedef void* (*MSFindSymbol_t)(void *image, const char *name);
//                MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
//                MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
                
                MSHookMessageEx(
                                objc_getClass("XBSnapshotContainerIdentity"),
                                @selector(snapshotContainerPath),
                                (IMP)&XBSnapshotContainer_Identity_snapshotContainerPath,
                                (IMP*)&orig_XBSnapshotContainerIdentity_snapshotContainerPath
                                );
                
                MSImageRef splashImage = MSGetImageByName("/System/Library/PrivateFrameworks/SplashBoard.framework/SplashBoard");
                void* XBValidateStoryboard_ptr = MSFindSymbol(splashImage, "_XBValidateStoryboard");
                MSHookFunction(XBValidateStoryboard_ptr, (void *)&new_XBValidateStoryboard, 0);
            }
        } else if (strstr(argv[0], "/jb/Applications/TweakSettings.app/") || (strstr(argv[0], "/jb/Applications/iCleaner.app/"))) {
            chineseWifiFixup();
//            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
//            typedef void (*MSHookFunction_t)(void *, void *, void **);
//            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            if (strstr(argv[0], "/jb/Applications/iCleaner.app/")) {
                MSHookFunction(setuid, (void*)hooked_setuid, 0);
                MSHookFunction(setgid, (void*)hooked_setgid, 0);
            } else {
                MSHookFunction(posix_spawn, (void*)hooked_posix_spawn, (void**)&orig_posix_spawn);
            }
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/CoreTelephony.framework/Support/CommCenter") == 0) {
//            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
//            typedef void* MSImageRef;
//            typedef void* (*MSGetImageByName_t)(const char *image_name);
//            typedef void* (*MSFindSymbol_t)(void *image, const char *name);
//
//            MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
//            MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
//            typedef void (*MSHookFunction_t)(void *, void *, void **);
//            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
            void* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
            MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
            return;
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/SocialLayer.framework/sociallayerd.app/sociallayerd") == 0) {
            NSBundle *appBundle = [[NSBundle alloc] initWithPath:@"/System/Library/PrivateFrameworks/SocialLayer.framework/sociallayerd.app"];
//            Class bundleClass = objc_getClass("NSBundle");
            
            overwriteMainNSBundle(appBundle);
            overwriteMainCFBundle();
            
            NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
            objcArgv[0] = appBundle.executablePath;
            [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
            
//            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
//            typedef void* MSImageRef;
//            typedef void* (*MSGetImageByName_t)(const char *image_name);
//            typedef void* (*MSFindSymbol_t)(void *image, const char *name);
//            
//            MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
//            MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
//            typedef void (*MSHookFunction_t)(void *, void *, void **);
//            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
            
            MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
            void* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
            MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/installd") == 0) {
//            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
//            typedef void (*MSHookMessageEx_t)(Class, SEL, IMP, IMP *);
//            MSHookMessageEx_t MSHookMessageEx = (MSHookMessageEx_t)dlsym(substrateHandle, "MSHookMessageEx");
            
            MSHookMessageEx(
                            objc_getClass("MIContainer"),
                            @selector(makeContainerLiveReplacingContainer:reason:waitForDeletion:withError:),
                            (IMP)&new_makeContainerLiveReplacingContainer,
                            (IMP*)&orig_makeContainerLiveReplacingContainer
                            );
        } else if (strcmp(argv[0], "/System/Library/VideoCodecs/SysBins/cfprefsd") == 0) {
//            void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
//            typedef void* MSImageRef;
//            typedef void (*MSHookFunction_t)(void *, void *, void **);
//            MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
//            
//            typedef void* (*MSGetImageByName_t)(const char *image_name);
//            typedef void* (*MSFindSymbol_t)(void *image, const char *name);
//
//            MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
//            MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
            
            MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
            void* CFPrefsGetPathForTriplet_ptr = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet");
            MSHookFunction(CFPrefsGetPathForTriplet_ptr, (void *)&new_CFPrefsGetPathForTriplet, (void **)&orig_CFPrefsGetPathForTriplet);
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
