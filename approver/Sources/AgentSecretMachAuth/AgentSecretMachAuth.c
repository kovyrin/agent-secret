#include "AgentSecretMachAuth.h"

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <string.h>

enum { agent_secret_auth_message_id = 0x4153 };

typedef struct {
    mach_msg_header_t header;
    uint8_t digest[32];
} agent_secret_auth_message;

int AgentSecretSendMachAuth(const char *name, const uint8_t digest[32]) {
    mach_port_t port = MACH_PORT_NULL;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    kern_return_t status = bootstrap_look_up(bootstrap_port, name, &port);
#pragma clang diagnostic pop
    if (status != KERN_SUCCESS) {
        return status;
    }

    agent_secret_auth_message message = {0};
    message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
    message.header.msgh_size = sizeof(message);
    message.header.msgh_remote_port = port;
    message.header.msgh_id = agent_secret_auth_message_id;
    memcpy(message.digest, digest, sizeof(message.digest));
    status = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                      message.header.msgh_size, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
    mach_port_deallocate(mach_task_self(), port);
    return status;
}
