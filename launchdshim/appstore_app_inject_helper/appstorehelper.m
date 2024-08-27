#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <spawn.h>
#include <utils.h>
#include "sandbox.h"

extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern XPC_RETURNS_RETAINED xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

BOOL isJITEnabled()
{
    int flags;
    csops(getpid(), 0, &flags, sizeof(flags));
    return (flags & CS_DEBUGGED) != 0;
}

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
        } else {
            init_bypassDyldLibValidation();
            dlopen("/var/jb/usr/lib/TweakInject.dylib", RTLD_NOW | RTLD_GLOBAL);
        }
    }
}
