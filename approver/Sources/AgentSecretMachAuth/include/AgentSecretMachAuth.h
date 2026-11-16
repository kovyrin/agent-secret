#ifndef AGENT_SECRET_MACH_AUTH_H
#define AGENT_SECRET_MACH_AUTH_H

#include <stdint.h>

int AgentSecretSendMachAuth(const char *name, const uint8_t digest[32]);

#endif
