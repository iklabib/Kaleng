package model

import (
	"os"
	"time"

	"codeberg.org/iklabib/kaleng/rlimit"
	"github.com/elastic/go-seccomp-bpf"
)

type Landlock struct {
	Files  []string `json:"files"` // fd:rwxc:/path
	Tty    bool     `json:"tty"`
	Shared bool     `json:"shared"`
	Tmp    bool     `json:"tmp"`
	VMInfo bool     `json:"vm_info"`
	Dns    bool     `json:"dns"`
	Certs  bool     `json:"certs"`
}

type KalengConfig struct {
	Seccomp    seccomp.Policy  `json:"seccomp"`
	Namespaces []string        `json:"namespaces"`
	Rlimits    []rlimit.Rlimit `json:"rlimits"`
	Landlock   `json:"landlock"`
	Uid        int `json:"uid"`
	Gid        int `json:"gid"`
}

type Metrics struct {
	Signal   os.Signal     `json:"signal"`
	ExitCode int           `json:"exit_code"`
	SysTime  time.Duration `json:"sys_time"`
	UserTime time.Duration `json:"time"`
	Memory   int64         `json:"memory"`
}

type Result struct {
	Stdout  string  `json:"stdout"`
	Stderr  string  `json:"stderr"`
	Message string  `json:"message"`
	Metric  Metrics `json:"metric"`
}
