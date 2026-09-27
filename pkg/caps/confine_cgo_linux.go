//go:build linux && cgo

package caps

// A build with cgo cannot use syscall.AllThreadsSyscall: the runtime refuses,
// because it cannot enumerate threads that C code started. So the clearing
// happens earlier than any Go code can run — in a constructor, which the C
// runtime calls before the Go runtime starts its first thread. Every thread the
// process ever has is then cloned from one that already holds nothing to pass
// on. runc's nsenter uses the same hook for the same reason.

/*
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <linux/capability.h>

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

__attribute__((constructor)) static void cloop_confine_capabilities(void) {
	struct __user_cap_header_struct hdr = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct data[2];

	// Fails with EINVAL on a kernel without ambient capabilities, which then
	// has none to clear.
	prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
	if (syscall(SYS_capget, &hdr, data) != 0) {
		return;
	}
	if (data[0].inheritable == 0 && data[1].inheritable == 0) {
		return;
	}
	data[0].inheritable = 0;
	data[1].inheritable = 0;
	syscall(SYS_capset, &hdr, data);
}
*/
import "C"

// clearInherited has nothing left to do: the constructor above ran before any
// thread existed. confine's verification still checks every thread, so a
// constructor that did not run is reported rather than assumed.
func clearInherited() error { return nil }
