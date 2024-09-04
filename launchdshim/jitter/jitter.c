#include <xpc/xpc.h>
#include <mach/mach.h>

#define PT_DETACH       11      /* stop tracing a process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */
#define PT_KILL 8
#define MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK 5
#define JBD_MSG_PROC_SET_DEBUGGED 23

int ptrace(int request, pid_t pid, caddr_t addr, int data);
extern int xpc_pipe_routine_reply(xpc_object_t reply);
void xpc_dictionary_get_audit_token(xpc_object_t xdict, audit_token_t *token);
extern int xpc_pipe_receive(mach_port_t port, XPC_GIVES_REFERENCE xpc_object_t *message);
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void * _Nullable buffer, size_t buffersize);
kern_return_t bootstrap_check_in(mach_port_t bootstrap_port, const char *service, mach_port_t *server_port);

int enableJIT(pid_t pid)
{
    int ret = ptrace(PT_ATTACHEXC, pid, 0, 0);
    if (ret != 0) return ret;
    for (int retries = 0; retries < 100; retries++) {
        usleep(1000); // decreased from 10000, probably better
        ret = ptrace(PT_DETACH, pid, 0, 0);
        if (ret == 0) {
            return ret;
        }
    }
    ptrace(PT_KILL, pid, 0, 0);
    return ret;
}

void jitterd_received_message(mach_port_t machPort, bool systemwide)
{
        xpc_object_t message = NULL;
        int err = xpc_pipe_receive(machPort, &message);
        if (err != 0) {
             // NSLog(@"xpc_pipe_receive error %d", err);
            return;
        }

        xpc_object_t reply = xpc_dictionary_create_reply(message);
        xpc_type_t messageType = xpc_get_type(message);
        int64_t msgId = -1;

        if (messageType == XPC_TYPE_DICTIONARY) {
            audit_token_t auditToken = {};
            xpc_dictionary_get_audit_token(message, &auditToken);
            // uid_t clientUid = audit_token_to_euid(auditToken);
            // pid_t clientPid = audit_token_to_pid(auditToken);
            msgId = xpc_dictionary_get_int64(message, "id");
//            char *description = xpc_copy_description(message);
//            free(description);

            switch (msgId) {
                case JBD_MSG_PROC_SET_DEBUGGED: {
                    int64_t result = 0;
                    pid_t pid = xpc_dictionary_get_int64(message, "pid");
                    result = enableJIT(pid);
                    xpc_dictionary_set_int64(reply, "result", result);
                    break;
                }
                default:
                    break;
            }
        }

        if (reply) {
//            char *description = xpc_copy_description(reply);
//             // NSLog(@"responding to %s message %lld with %s", systemwide ? "systemwide" : "", msgId, description);
//            free(description);
            xpc_pipe_routine_reply(reply);
//            if (err != 0) {
                 // NSLog(@"Error %d sending response", err);
//            }
            xpc_release(reply);
        }
        xpc_release(message);
}

__attribute__((constructor)) static void init() {
    memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(), 10, NULL, 0);
}

int main(int argc, char* argv[])
{
        mach_port_t machPort = 0;
        kern_return_t kr = bootstrap_check_in(bootstrap_port, "com.hrtowii.jitterd", &machPort);
        if (kr != KERN_SUCCESS) {
            // NSLog(@"Failed com.hrtowii.jitterd.systemwide bootstrap check in: %d (%s)", kr, mach_error_string(kr));
            return 1;
        }

        dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)machPort, 0, dispatch_get_main_queue());
        dispatch_source_set_event_handler(source, ^{
            jitterd_received_message(machPort, true);
        });
        dispatch_resume(source);

        dispatch_main();
        return 0;
}
