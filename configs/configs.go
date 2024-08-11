package configs

import (
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

type Cgroup struct {
	MaxMemory      string `config:"max_memory" json:"max_memory" yaml:"max_memory"`
	MaxPids        int    `config:"max_pids" json:"max_pids" yaml:"max_pids"`
	MaxDepth       int    `config:"max_depth" json:"max_depth" yaml:"max_depth"`
	MaxDescendants int    `config:"max_descendants" json:"max_descendants" yaml:"max_descendants"`
	Cpu            `config:"cpu" json:"cpu" yaml:"max_procs"`
}

// no-op if default value
type Cpu struct {
	Time   uint `json:"time"`   // cpu.max $MAX
	Period uint `json:"period"` // cpu.max $PERIOD
	Weight uint `json:"weight"` // cpu.weight
}

type KalengConfig struct {
	Envs       map[string]string `json:"envs"`
	Namespaces []string          `json:"namespaces"`
	Rlimits    []rlimit.Rlimit   `json:"rlimits"`
	Seccomp    seccomp.Policy    `json:"seccomp"`
	Cgroup     `json:"cgroup"`
	Landlock   `json:"landlock"`
	Uid        int `json:"uid"`
	Gid        int `json:"gid"`
}
