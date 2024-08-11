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
	Envs       map[string]string `config:"envs" json:"envs"`
	Namespaces []string          `config:"namespaces"  json:"namespaces"`
	Rlimits    []rlimit.Rlimit   `config:"rlimits" json:"rlimits"`
	Seccomp    seccomp.Policy    `config:"seccomp" json:"seccomp"`
	Cgroup     `config:"cgroup" json:"cgroup"`
	Landlock   `config:"landlock" json:"landlock"`
	Uid        int `config:"uid" json:"uid"`
	Gid        int `config:"gid" json:"gid"`
	TimeLimit  int `config:"time_limit" json:"time_limit"` // s
}
