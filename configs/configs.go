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
	Time   uint `config:"time" yaml:"time" json:"time"`       // cpu.max $MAX
	Period uint `config:"period" yaml:"period" json:"period"` // cpu.max $PERIOD
	Weight uint `config:"weight" yaml:"weight" json:"weight"` // cpu.weight
}

type Bind struct {
	Source string `config:"source" yaml:"source" json:"source"`
	Target string `config:"target" yaml:"target" json:"target"`
	FsType string `config:"fstype" yaml:"fstype" json:"fstype"`
	Data   string `config:"data" yaml:"data" json:"data"`
}

type KalengConfig struct {
	Cgroup     `config:"cgroup" json:"cgroup"`
	Envs       map[string]string `config:"envs" json:"envs"`
	Namespaces []string          `config:"namespaces"  json:"namespaces"`
	Rlimits    []rlimit.Rlimit   `config:"rlimits" yaml:"rlimits" json:"rlimits"`
	Seccomp    seccomp.Policy    `config:"seccomp" yaml:"seccomp" json:"seccomp"`
	User       string            `config:"user" yaml:"user" json:"user"`
	Group      string            `config:"group" yaml:"group" json:"group"`
	TimeLimit  int               `config:"time_limit" yaml:"time_limit" json:"time_limit"` // s
	Files      []string          `config:"files" yaml:"files" json:"files"`                // fd:rwxc:/path
	Binds      []Bind            `config:"binds" yaml:"binds" json:"binds"`
}
