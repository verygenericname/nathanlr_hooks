#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
//#include <substrate.h>
//#include <libhooker/libhooker.h>
#include <spawn.h>
#include <unistd.h>
#include <signal.h>
#import <Foundation/Foundation.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <objc/runtime.h>
#include <utils.h>
//#include <sys/kern_memorystatus.h>
#include <litehook.h>
#include "../sandbox.h"

#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA

@interface NSBundle(private)
- (id)_cfBundle;
@end

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

int (*DBSystemAppMain)(int argc, char *argv[], char *envp[], char* apple[]);

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

static BOOL (*orig_isLoaded)(NSBundle *self, SEL _cmd);

BOOL hook_isLoaded(NSBundle *self, SEL _cmd) {
    NSString *targetBundlePath = @"/System/Library/CoreServices/CarPlay.app";

    if ([[self bundlePath] isEqualToString:targetBundlePath]) {
        return YES;
    }

    return orig_isLoaded(self, _cmd);
}

uint64_t (*orig_LSFindBundleWithInfo_NoIOFiltered)(id, uint64_t, CFStringRef, Boolean, CFURLRef, UInt64, NSString *, BOOL (^)(id, uint64_t, const id), NSError **);

uint64_t new_LSFindBundleWithInfo_NoIOFiltered(id arg1, uint64_t arg2, CFStringRef arg3, Boolean arg4, CFURLRef arg5, UInt64 arg6, NSString *arg7, BOOL (^arg8)(id, uint64_t, const id), NSError **arg9) {
    
    CFURLRef newUrl = NULL;

    if (arg5 != NULL) {
        NSString *cfURLString = (__bridge NSString *)CFURLCopyPath(arg5);
        NSString *strippedLast = [cfURLString stringByDeletingLastPathComponent];
        NSString *appName = [cfURLString lastPathComponent];
        
        if ([strippedLast isEqualToString:@"/System/Library/VideoCodecs/CoreServices"]) {
            NSString *baseURLString = @"/System/Library/CoreServices/";
            NSString *appendURLString = [baseURLString stringByAppendingString:appName];
            
            newUrl = CFURLCreateWithString(kCFAllocatorDefault, (__bridge CFStringRef)appendURLString, NULL);
        } else if ([strippedLast isEqualToString:@"/System/Library/VideoCodecs/Applications"]) {
            NSString *baseURLString = @"/Applications/";
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

int main(int argc, char *argv[], char *envp[], char* apple[]) {
    @autoreleasepool {
        JB_SandboxExtensions = getSandboxExtensionsFromPlist();
        if (JB_SandboxExtensions) {
            unsandbox();
            free(JB_SandboxExtensions);
        }
        
        if (enableJIT(getpid()) != 0) {
//            NSLog(@"[-] Failed to enable JIT");
            exit(1);
        }
        
        litehook_hook_function(csops, csops_hook);
        litehook_hook_function(csops_audittoken, csops_audittoken_hook);
        
//        init_bypassDyldLibValidation();
        
        NSString *bundlePath = @"/System/Library/CoreServices/CarPlay.app";
        NSBundle *appBundle = [[NSBundle alloc] initWithPath:bundlePath];
        
        overwriteMainNSBundle(appBundle);
        overwriteMainCFBundle();
        
        NSMutableArray<NSString *> *objcArgv = NSProcessInfo.processInfo.arguments.mutableCopy;
        objcArgv[0] = appBundle.executablePath;
        [NSProcessInfo.processInfo performSelector:@selector(setArguments:) withObject:objcArgv];
//        NSProcessInfo.processInfo.processName = appBundle.infoDictionary[@"CFBundleExecutable"];
//        *_CFGetProgname() = NSProcessInfo.processInfo.processName.UTF8String;

        void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        typedef void (*MSHookMessageEx_t)(Class, SEL, IMP, IMP *);
        MSHookMessageEx_t MSHookMessageEx = (MSHookMessageEx_t)dlsym(substrateHandle, "MSHookMessageEx");
        typedef void* MSImageRef;
        typedef void (*MSHookFunction_t)(void *, void *, void **);
        MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
        typedef void* (*MSGetImageByName_t)(const char *image_name);
        typedef void* (*MSFindSymbol_t)(void *image, const char *name);
        MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
        MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
        
        MSHookMessageEx(objc_getClass("NSBundle"), @selector(isLoaded), (IMP)hook_isLoaded, (IMP *)&orig_isLoaded);
        
        void *handle = dlopen("/System/Library/PrivateFrameworks/DashBoard.framework/DashBoard", RTLD_GLOBAL);
        dlopen("/var/jb/usr/lib/TweakInject.dylib", RTLD_NOW | RTLD_GLOBAL);
        
//        MSImageRef coreServicesImage = MSGetImageByName("/System/Library/Frameworks/CoreServices.framework/CoreServices");
//        uint64_t* _LSFindBundleWithInfo_NoIOFiltered_ptr = MSFindSymbol(coreServicesImage, "__LSFindBundleWithInfo_NoIOFiltered");
//        MSHookFunction(_LSFindBundleWithInfo_NoIOFiltered_ptr, (void *)&new_LSFindBundleWithInfo_NoIOFiltered, (void **)&orig_LSFindBundleWithInfo_NoIOFiltered);
        
        DBSystemAppMain = dlsym(handle, "DBSystemAppMain");
        return DBSystemAppMain(argc, argv, envp, apple);
    }
}

