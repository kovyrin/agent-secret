//go:build darwin

package messageauth

/*
#cgo CFLAGS: -Wall -Werror -Wno-deprecated-declarations
#cgo LDFLAGS: -lbsm
#include <bsm/libbsm.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum { agentsecret_auth_message_id = 0x4153 };

typedef struct {
	mach_msg_header_t header;
	uint8_t digest[32];
} agentsecret_auth_message;

typedef struct {
	agentsecret_auth_message message;
	mach_msg_max_trailer_t trailer;
} agentsecret_auth_received;

static kern_return_t agentsecret_auth_listen(char *name, mach_port_t *port) {
	kern_return_t status = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, port);
	if (status != KERN_SUCCESS) return status;
	status = bootstrap_register(bootstrap_port, name, *port);
	if (status != KERN_SUCCESS) {
		mach_port_destroy(mach_task_self(), *port);
		*port = MACH_PORT_NULL;
	}
	return status;
}

static void agentsecret_auth_close(mach_port_t port) {
	if (port != MACH_PORT_NULL) mach_port_destroy(mach_task_self(), port);
}

static kern_return_t agentsecret_auth_send(char *name, const uint8_t *digest) {
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t status = bootstrap_look_up(bootstrap_port, name, &port);
	if (status != KERN_SUCCESS) return status;
	agentsecret_auth_message message = {0};
	message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
	message.header.msgh_size = sizeof(message);
	message.header.msgh_remote_port = port;
	message.header.msgh_id = agentsecret_auth_message_id;
	memcpy(message.digest, digest, sizeof(message.digest));
	status = mach_msg(&message.header, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
		message.header.msgh_size, 0, MACH_PORT_NULL, 1000, MACH_PORT_NULL);
	mach_port_deallocate(mach_task_self(), port);
	return status;
}

static kern_return_t agentsecret_auth_receive(mach_port_t port, uint32_t timeout_ms,
	uint8_t *digest, pid_t *pid, uint32_t *pidversion, uid_t *uid) {
	agentsecret_auth_received received = {0};
	kern_return_t status = mach_msg(&received.message.header,
		MACH_RCV_MSG | MACH_RCV_TIMEOUT |
		MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0) |
		MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT),
		0, sizeof(received), port, timeout_ms, MACH_PORT_NULL);
	if (status != KERN_SUCCESS) return status;
	if (received.message.header.msgh_bits & MACH_MSGH_BITS_COMPLEX ||
		received.message.header.msgh_remote_port != MACH_PORT_NULL) {
		mach_msg_destroy(&received.message.header);
		return KERN_INVALID_ARGUMENT;
	}
	if (received.message.header.msgh_id != agentsecret_auth_message_id ||
		received.message.header.msgh_size != sizeof(agentsecret_auth_message)) return KERN_INVALID_ARGUMENT;
	mach_msg_audit_trailer_t *trailer = (mach_msg_audit_trailer_t *)
		((uint8_t *)&received + ((received.message.header.msgh_size + 3) & ~3));
	if (trailer->msgh_trailer_type != MACH_MSG_TRAILER_FORMAT_0 ||
		trailer->msgh_trailer_size < sizeof(*trailer)) return KERN_INVALID_ARGUMENT;
	memcpy(digest, received.message.digest, 32);
	*pid = audit_token_to_pid(trailer->msgh_audit);
	*pidversion = (uint32_t)audit_token_to_pidversion(trailer->msgh_audit);
	*uid = audit_token_to_euid(trailer->msgh_audit);
	return KERN_SUCCESS;
}

static int agentsecret_auth_timed_out(kern_return_t status) {
	return status == MACH_RCV_TIMED_OUT;
}
*/
import "C"

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"time"
	"unsafe"

	"github.com/kovyrin/agent-secret/internal/randid"
)

var (
	ErrTimeout       = errors.New("request attestation timed out")
	ErrFrameMismatch = errors.New("request attestation frame mismatch")
)

type Identity struct {
	PID        int
	PIDVersion uint32
	UID        int
}

type Port struct {
	name string
	port C.mach_port_t
}

func NewPort() (*Port, error) {
	id, err := randid.Generate(nil, "")
	if err != nil {
		return nil, err
	}
	name := fmt.Sprintf("com.kovyrin.agentsecret.auth.%d.%s", os.Getpid(), id)
	nameCString := C.CString(name)
	defer C.free(unsafe.Pointer(nameCString))
	var port C.mach_port_t
	if status := C.agentsecret_auth_listen(nameCString, &port); status != C.KERN_SUCCESS {
		return nil, fmt.Errorf("register request attestation port: Mach status %d", status)
	}
	return &Port{name: name, port: port}, nil
}

func (p *Port) Name() string { return p.name }

func (p *Port) Close() { C.agentsecret_auth_close(p.port) }

func Send(name string, frame []byte) error {
	digest := sha256.Sum256(frame)
	nameCString := C.CString(name)
	defer C.free(unsafe.Pointer(nameCString))
	if status := C.agentsecret_auth_send(nameCString, (*C.uint8_t)(unsafe.Pointer(&digest[0]))); status != C.KERN_SUCCESS {
		return fmt.Errorf("send request attestation: Mach status %d", status)
	}
	return nil
}

func (p *Port) Receive(frame []byte, timeout time.Duration) (Identity, error) {
	digest := sha256.Sum256(frame)
	var received [32]byte
	var pid C.pid_t
	var pidVersion C.uint32_t
	var uid C.uid_t
	if timeout <= 0 {
		return Identity{}, ErrTimeout
	}
	milliseconds := timeout.Milliseconds()
	if milliseconds == 0 {
		milliseconds = 1
	}
	if milliseconds > math.MaxUint32 {
		milliseconds = math.MaxUint32
	}
	status := C.agentsecret_auth_receive(p.port, C.uint32_t(milliseconds),
		(*C.uint8_t)(unsafe.Pointer(&received[0])), &pid, &pidVersion, &uid)
	if C.agentsecret_auth_timed_out(status) != 0 {
		return Identity{}, ErrTimeout
	}
	if status != C.KERN_SUCCESS {
		return Identity{}, fmt.Errorf("receive request attestation: Mach status %d", status)
	}
	if digest != received {
		return Identity{}, ErrFrameMismatch
	}
	return Identity{PID: int(pid), PIDVersion: uint32(pidVersion), UID: int(uid)}, nil
}
