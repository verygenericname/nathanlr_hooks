#include <xpc/xpc.h>
#include <mach/mach.h>

#define PT_DETACH       11      /* stop tracing a process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */
#define PT_KILL 8
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define JBD_MSG_PROC_SET_DEBUGGED 23

int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void * _Nullable buffer, size_t buffersize);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service, mach_port_t *server_port);

int enableJIT(pid_t pid)
{
    if (ptrace(PT_ATTACHEXC, pid, 0, 0) != 0) return -1;
    for (int retries = 0; retries < 50; retries++) {
        usleep(1000); // decreased from 10000, probably better
        if (!ptrace(PT_DETACH, pid, 0, 0)) {
            return 0;
        }
    }
    ptrace(PT_KILL, pid, 0, 0);
    return -1;
}

void jitterd_received_message(mach_port_t machPort)
{
    xpc_object_t message = NULL;
    int err = xpc_pipe_receive(machPort, &message);
    if (err != 0) {
        // NSLog(@"xpc_pipe_receive error %d", err);
        return;
    }
    
    xpc_object_t reply = xpc_dictionary_create_reply(message);
    
    if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
        if (xpc_dictionary_get_value(message, "pid")) {
            int64_t result = enableJIT(xpc_dictionary_get_int64(message, "pid"));
            xpc_dictionary_set_int64(reply, "result", result);
        }
    }
    xpc_pipe_routine_reply(reply);
    xpc_release(message);
    xpc_release(reply);
}

__attribute__((constructor)) static void init() {
    memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(), 10, NULL, 0);
}

int main(int argc, char* argv[])
{
        mach_port_t machPort = 0;
        kern_return_t kr = bootstrap_check_in(bootstrap_port, "com.hrtowii.jitterd", &machPort);

        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, machPort, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(source, ^{
            jitterd_received_message(machPort);
        });
        dispatch_resume(source);

        dispatch_main();
        return 0;
}
