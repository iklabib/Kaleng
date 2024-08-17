package configs

import (
	"codeberg.org/iklabib/kaleng/rlimit"
	"github.com/elastic/go-seccomp-bpf"
)

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

type Bind struct {
	Source string `config:"source" json:"source"`
	Target string `config:"target" json:"target"`
	FsType string `config:"fstype" json:"fstype"`
	Data   string `config:"data" json:"data"`
}

type KalengConfig struct {
	Cgroup     `config:"cgroup" json:"cgroup"`
	Envs       map[string]string `config:"envs" json:"envs"`
	Namespaces []string          `config:"namespaces"  json:"namespaces"`
	Rlimits    []rlimit.Rlimit   `config:"rlimits" json:"rlimits"`
	Seccomp    seccomp.Policy    `config:"seccomp" json:"seccomp"`
	User       string            `config:"user" json:"user"`
	Group      string            `config:"group" json:"group"`
	TimeLimit  int               `config:"time_limit" json:"time_limit"` // s
	Files      []string          `config:"files" json:"files"`           // fd:rwxc:/path
	Binds      []Bind            `config:"binds" json:"binds"`
}
