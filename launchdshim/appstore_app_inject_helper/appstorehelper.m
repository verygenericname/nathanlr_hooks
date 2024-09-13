#include <unistd.h>
#include <stdio.h>
#include <dlfcn.h>
#include <dirent.h>
#include <string.h>
#include <spawn.h>
#include <utils.h>
#include <mach/mach.h>

extern int xpc_pipe_routine(xpc_object_t pipe, xpc_object_t message, XPC_GIVES_REFERENCE xpc_object_t *reply);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern XPC_RETURNS_RETAINED xpc_object_t xpc_pipe_create_from_port(mach_port_t port, uint32_t flags);
kern_return_t bootstrap_look_up(mach_port_t port, const char *service, mach_port_t *server_port);
int64_t sandbox_extension_consume(const char *extension_token);

mach_port_t jitterdSystemWideMachPort(void)
{
    mach_port_t outPort = MACH_PORT_NULL;
    kern_return_t kr = KERN_SUCCESS;
    kr = bootstrap_look_up(bootstrap_port, "com.hrtowii.jitterd", &outPort);

    if (kr != KERN_SUCCESS) return MACH_PORT_NULL;
    return outPort;
}

xpc_object_t sendjitterdMessageSystemWide(xpc_object_t xdict)
{
    xpc_object_t jitterd_xreply = NULL;
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
    return jitterd_xreply;
}

//#define JBD_MSG_PROC_SET_DEBUGGED 23
int64_t jitterd(pid_t pid)
{
    int64_t result = 0;
    xpc_object_t message = xpc_dictionary_create_empty();
//    xpc_dictionary_set_int64(message, "id", JBD_MSG_PROC_SET_DEBUGGED);
    xpc_dictionary_set_int64(message, "pid", pid);
    
    xpc_object_t reply = sendjitterdMessageSystemWide(message);
    xpc_release(message);
    
    if (reply) {
        result = xpc_dictionary_get_int64(reply, "result");
        xpc_release(reply);
    }
    
    return result;
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

int enableJIT(pid_t pid)
{
    for (int retries = 0; retries < 50; retries++)
    {
//            NSLog(@"Hopefully enabled jit");
        if (jitterd(pid) == 0)
        {
//                NSLog(@"[+] JIT has heen enabled with PT_TRACE_ME");
            return true;
        }
        usleep(10000);
    }
    return false;
}

__attribute__((constructor)) static void init(int argc, char **argv, char *envp[]) {
    @autoreleasepool {
        unsandbox();
        
        if (enableJIT(getpid())) {
            unsetenv("DYLD_INSERT_LIBRARIES");
            init_bypassDyldLibValidation();
            dlopen("/var/jb/usr/lib/TweakInject.dylib", RTLD_NOW | RTLD_GLOBAL);
        }
    }
}
