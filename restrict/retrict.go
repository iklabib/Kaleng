package restrict

import (
	"syscall"

	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/rlimit"
	"codeberg.org/iklabib/kaleng/util"
	"github.com/elastic/go-seccomp-bpf"
	"github.com/shoenig/go-landlock"
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

func EnforceLandlock(config model.Landlock) {
	var paths []*landlock.Path

	if config.Tty {
		paths = append(paths, landlock.TTY())
	}

	if config.Shared {
		paths = append(paths, landlock.Shared())
	}

	if config.Tmp {
		paths = append(paths, landlock.Tmp())
	}

	if config.Dns {
		paths = append(paths, landlock.DNS())
	}

	if config.VMInfo {
		paths = append(paths, landlock.VMInfo())
	}

	for _, v := range config.Files {
		lp, err := landlock.ParsePath(v)
		if err != nil {
			util.Bail(err)
		}
		paths = append(paths, lp)
	}

	ll := landlock.New(paths...)
	if err := ll.Lock(landlock.Mandatory); err != nil {
		util.Bail(err)
	}
}

// keep in mind that clone is blocked by docker default seccomp profile
// unless you have CAP_SYS_ADMIN
func GetCloneFlags(namespaces []string) int {
	if len(namespaces) == 0 {
		util.MessageBail("no namespaces provided")
	}

	var cloneFlags int
	for _, ns := range namespaces {
		switch ns {
		case "CLONE_NEWCGROUP":
			cloneFlags |= syscall.CLONE_NEWCGROUP
		case "CLONE_NEWUTS":
			cloneFlags |= syscall.CLONE_NEWUTS
		case "CLONE_NEWIPC":
			cloneFlags |= syscall.CLONE_NEWIPC
		case "CLONE_NEWNS":
			cloneFlags |= syscall.CLONE_NEWNS
		case "CLONE_NEWUSER":
			cloneFlags |= syscall.CLONE_NEWUSER
		case "CLONE_NEWPID":
			cloneFlags |= syscall.CLONE_NEWPID
		case "CLONE_NEWNET":
			cloneFlags |= syscall.CLONE_NEWNET
		}
	}
	return cloneFlags
}
