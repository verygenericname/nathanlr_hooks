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
#import <CoreFoundation/CoreFoundation.h>
#include <sys/param.h>
#include <libgen.h>
#include <litehook.h>
#include "sandbox.h"

#define SYSCALL_CSOPS 0xA9
#define SYSCALL_CSOPS_AUDITTOKEN 0xAA
#define CS_DEBUGGED 0x10000000

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

BOOL preferencePlistNeedsRedirection(NSString *plistPath)
{
    if ([plistPath hasPrefix:@"/private/var/mobile/Containers"] || [plistPath hasPrefix:@"/var/db"] || [plistPath hasPrefix:@"/var/jb"]) return NO;

    NSString *plistName = plistPath.lastPathComponent;

    if ([plistName hasPrefix:@"com.apple."] || [plistName hasPrefix:@"systemgroup.com.apple."] || [plistName hasPrefix:@"group.com.apple."]) return NO;

    NSArray *additionalSystemPlistNames = @[
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
//        @"APMExperimentSuiteName.plist",
//        @"APMAnalyticsSuiteName.plist",
//        @"com.tigisoftware.Filza.plist",
//        @"com.serena.Antoine.plist",
//        @"org.coolstar.SileoStore.plist",
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

int (*__CFXPreferencesDaemon_main)(int argc, char *argv[], char *envp[], char* apple[]);

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
        
        void *substrateHandle = dlopen("/var/jb/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate", RTLD_NOW);
        typedef void* MSImageRef;
        typedef void (*MSHookFunction_t)(void *, void *, void **);
        MSHookFunction_t MSHookFunction = (MSHookFunction_t)dlsym(substrateHandle, "MSHookFunction");
        
        typedef void* (*MSGetImageByName_t)(const char *image_name);
        typedef void* (*MSFindSymbol_t)(void *image, const char *name);

        MSGetImageByName_t MSGetImageByName = (MSGetImageByName_t)dlsym(substrateHandle, "MSGetImageByName");
        MSFindSymbol_t MSFindSymbol = (MSFindSymbol_t)dlsym(substrateHandle, "MSFindSymbol");
        
        MSImageRef coreFoundationImage = MSGetImageByName("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation");
        void* CFPrefsGetPathForTriplet_ptr = MSFindSymbol(coreFoundationImage, "__CFPrefsGetPathForTriplet");
        MSHookFunction(CFPrefsGetPathForTriplet_ptr, (void *)&new_CFPrefsGetPathForTriplet, (void **)&orig_CFPrefsGetPathForTriplet);
        
        
        void *handle = dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", RTLD_GLOBAL);
        __CFXPreferencesDaemon_main = dlsym(handle, "__CFXPreferencesDaemon_main");
        return __CFXPreferencesDaemon_main(argc, argv, envp, apple);
    }
}
