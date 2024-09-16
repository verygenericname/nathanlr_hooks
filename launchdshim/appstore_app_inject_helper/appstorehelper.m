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
        if (!jitterd(pid))
        {
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
