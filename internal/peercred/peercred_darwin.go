//go:build darwin

package peercred

/*
#cgo darwin CFLAGS: -Wall -Werror
#include <errno.h>
#include <libproc.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syslimits.h>
#include <sys/types.h>
#include <sys/ucred.h>
#include <unistd.h>

enum {
	agentsecret_proc_path_size = PROC_PIDPATHINFO_MAXSIZE,
	agentsecret_path_size = PATH_MAX
};

static int agentsecret_getpeereid(int fd, uid_t *uid, gid_t *gid) {
	return getpeereid(fd, uid, gid);
}

static int agentsecret_peerpid(int fd, pid_t *pid) {
	socklen_t len = sizeof(*pid);
	return getsockopt(fd, 0, LOCAL_PEERPID, pid, &len);
}

static int agentsecret_peercred(int fd, uid_t *uid, gid_t *gid) {
	struct xucred cred;
	socklen_t len = sizeof(cred);
	if (getsockopt(fd, 0, LOCAL_PEERCRED, &cred, &len) != 0) {
		return -1;
	}
	if (cred.cr_version != XUCRED_VERSION || cred.cr_ngroups <= 0) {
		errno = EINVAL;
		return -1;
	}
	*uid = cred.cr_uid;
	*gid = cred.cr_groups[0];
	return 0;
}

static int agentsecret_pidpath(pid_t pid, char *buf, size_t size) {
	int ret = proc_pidpath(pid, buf, (uint32_t)size);
	if (ret <= 0) {
		return -1;
	}
	return ret;
}

static int agentsecret_pidcwd(pid_t pid, char *buf, size_t size) {
	struct proc_vnodepathinfo info;
	int ret = proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, sizeof(info));
	if (ret <= 0 || info.pvi_cdir.vip_path[0] == '\0') {
		errno = ENOENT;
		return -1;
	}
	strlcpy(buf, info.pvi_cdir.vip_path, size);
	return 0;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func inspectFD(fd uintptr) (Info, error) {
	var uid C.uid_t
	var gid C.gid_t
	if _, err := C.agentsecret_getpeereid(C.int(fd), &uid, &gid); err != nil {
		return Info{}, fmt.Errorf("getpeereid: %w", err)
	}

	var credUID C.uid_t
	var credGID C.gid_t
	if _, err := C.agentsecret_peercred(C.int(fd), &credUID, &credGID); err != nil {
		return Info{}, fmt.Errorf("LOCAL_PEERCRED: %w", err)
	}
	if credUID != uid || credGID != gid {
		return Info{}, fmt.Errorf("%w: getpeereid and LOCAL_PEERCRED disagree", ErrMissingMetadata)
	}

	var pid C.pid_t
	if _, err := C.agentsecret_peerpid(C.int(fd), &pid); err != nil {
		return Info{}, fmt.Errorf("LOCAL_PEERPID: %w", err)
	}

	exe := make([]C.char, int(C.agentsecret_proc_path_size))
	if _, err := C.agentsecret_pidpath(pid, (*C.char)(unsafe.Pointer(&exe[0])), C.size_t(len(exe))); err != nil {
		return Info{}, fmt.Errorf("proc_pidpath: %w", err)
	}

	cwd := make([]C.char, int(C.agentsecret_path_size))
	if _, err := C.agentsecret_pidcwd(pid, (*C.char)(unsafe.Pointer(&cwd[0])), C.size_t(len(cwd))); err != nil {
		return Info{}, fmt.Errorf("PROC_PIDVNODEPATHINFO: %w", err)
	}

	return Info{
		UID:            int(uid),
		GID:            int(gid),
		PID:            int(pid),
		ExecutablePath: C.GoString((*C.char)(unsafe.Pointer(&exe[0]))),
		CWD:            C.GoString((*C.char)(unsafe.Pointer(&cwd[0]))),
	}, nil
}
