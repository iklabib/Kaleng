package restrict

import (
	"fmt"
	"os"
	"syscall"

	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/rlimit"
	"codeberg.org/iklabib/kaleng/util"
	"github.com/elastic/go-seccomp-bpf"
	"github.com/shoenig/go-landlock"
)

func SetEnvs(envs map[string]string) {
	os.Clearenv()

	for k, v := range envs {
		if err := os.Setenv(k, v); err != nil {
			util.Bail(err)
		}
	}
}

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

var namespacesMap map[string]uintptr = map[string]uintptr{
	"CGROUP": syscall.CLONE_NEWCGROUP,
	"UTS":    syscall.CLONE_NEWUTS,
	"IPC":    syscall.CLONE_NEWIPC,
	"MNT":    syscall.CLONE_NEWNS,
	"USER":   syscall.CLONE_NEWUSER,
	"PID":    syscall.CLONE_NEWPID,
	"NET":    syscall.CLONE_NEWNET,
	"TIME":   syscall.CLONE_NEWTIME,
}

// keep in mind that clone is blocked by docker default seccomp profile unless you have CAP_SYS_ADMIN
// on Debian based system you need to enable kernel.unprivileged_userns_clone
func GetNamespaceFlag(namespaces []string) uintptr {
	var cloneFlags uintptr
	for _, key := range namespaces {
		if ns, ok := namespacesMap[key]; ok {
			cloneFlags |= ns
		} else {
			err := fmt.Errorf("invalid namespace option '%s'", key)
			util.Bail(err)
		}
	}
	return cloneFlags
}
