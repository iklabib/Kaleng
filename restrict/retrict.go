package restrict

import (
	"syscall"

	"codeberg.org/iklabib/kaleng/rlimit"
	"codeberg.org/iklabib/kaleng/util"
	"github.com/elastic/go-seccomp-bpf"
)

func EnforceSeccomp(policy seccomp.Policy) {
	if !seccomp.Supported() {
		util.MessageBail("seccomp is not supported")
	}

	filter := seccomp.Filter{
		NoNewPrivs: true,
		Flag:       seccomp.FilterFlagTSync,
		Policy:     policy,
	}

	util.Bail(seccomp.LoadFilter(filter))
}

func PrivelegeDrop(uid, gid int) {
	if uid == 0 {
		util.MessageBail("uid 0 is not allowed")
	}

	if err := syscall.Setgroups([]int{gid}); err != nil {
		util.MessageBail("failed to set groups")
	}

	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		util.MessageBail("failed to set uid")
	}

	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		util.MessageBail("failed to set uid")
	}
}

func SetRlimits(rlimits []rlimit.Rlimit) {
	for _, rl := range rlimits {
		util.Bail(rl.ApplyLimit())
	}
}

func SetNamespaces(namespaces []string) {
}
