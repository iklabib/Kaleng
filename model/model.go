package model

import (
	"os"
	"time"
)

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
