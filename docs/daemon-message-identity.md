# Daemon request identity research

Status: implementation research for the 0.1.1 security fix.

The Unix stream used by Agent Secret does not attach a sender identity to each
JSON frame. XNU's `LOCAL_PEERPID` reflects the socket's last owner, and
`LOCAL_PEERTOKEN` resolves an audit token for that process when queried. A
process can write a frame, then `execve` a trusted binary before the daemon
accepts or handles it. Pinning `LOCAL_PEERTOKEN` at accept detects later image
changes but cannot identify the image that wrote buffered bytes.

A Mach message carries a kernel supplied audit trailer for the sender of that
message. Its PID version can be compared with `LOCAL_PEERTOKEN` on the Unix
connection. A per-connection Mach port and a SHA-256 digest of the exact JSON
frame can bind a request to the code image that sent the attestation. The port
must be unique to the connection, each attestation must be consumed once, and
the daemon must reject a missing or mismatched audit token before acting on the
request. The accepted Unix peer pin remains useful for detecting image changes
while a request is pending.

The macOS host probe registered a named Mach port with `bootstrap_register`,
resolved it with `bootstrap_look_up`, and registered the same temporary name
again after the first process exited. It also resolved a port registered under
`launchctl asuser` from the current app bootstrap context, and resolved a port
registered here from that user context. These checks do not cover every login
or SSH bootstrap layout. The opt-in `TestMachSenderTokenPrecedesExecImage`
regression sends a Mach attestation and
Unix frame from a process, then executes `/bin/sleep` in that same PID. The
received audit token retains the sending PID version while `LOCAL_PEERTOKEN`
reports the later image. `TestAuthenticatedServerBindsExactFrame` verifies the
daemon accepts an attested frame and rejects a different frame on that port.

Sources:

- [Apple XNU Unix socket options](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_usrreq.c)
- [Apple XNU socket owner tracking](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket.c)
- [Apple Mach message audit trailer](https://developer.apple.com/documentation/kernel/mach_msg_audit_trailer_t)
- [Apple guest audit attribute](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys)
