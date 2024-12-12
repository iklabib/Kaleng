package rlimit

import (
	"fmt"
	"syscall"
)

const (
	RLIMIT_AS     = "RLIMIT_AS"
	RLIMIT_CPU    = "RLIMIT_CPU"
	RLIMIT_CORE   = "RLIMIT_CORE"
	RLIMIT_DATA   = "RLIMIT_DATA"
	RLIMIT_FSIZE  = "RLIMIT_FSIZE"
	RLIMIT_NOFILE = "RLIMIT_NOFILE"
	RLIMIT_STACK  = "RLIMIT_STACK"
)

type Rlimit struct {
	Resource string `config:"resource" yaml:"resource" json:"resource"`
	Soft     uint64 `config:"soft" yaml:"soft" json:"soft"`
	Hard     uint64 `config:"hard" yaml:"soft" json:"hard"`
}

func (rl Rlimit) ApplyLimit() error {
	resource := -1
	switch rl.Resource {
	case RLIMIT_AS:
		resource = syscall.RLIMIT_AS
	case RLIMIT_CPU:
		resource = syscall.RLIMIT_CPU
	case RLIMIT_CORE:
		resource = syscall.RLIMIT_CORE
	case RLIMIT_DATA:
		resource = syscall.RLIMIT_DATA
	case RLIMIT_FSIZE:
		resource = syscall.RLIMIT_FSIZE
	case RLIMIT_NOFILE:
		resource = syscall.RLIMIT_NOFILE
	case RLIMIT_STACK:
		resource = syscall.RLIMIT_STACK
	default:
		return fmt.Errorf("unknown rlimit resource option '%s'", rl.Resource)
	}

	limit := &syscall.Rlimit{Cur: rl.Soft, Max: rl.Hard}
	return syscall.Setrlimit(resource, limit)
}
