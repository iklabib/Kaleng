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
	WallTime time.Duration `json:"wall_time"`
	Memory   int64         `json:"memory"`
}

type Result struct {
	Stdout  string   `json:"stdout"`
	Message []string `json:"message"`
	Metric  Metrics  `json:"metric"`
}
