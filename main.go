package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/restrict"
	"codeberg.org/iklabib/kaleng/util"
	"github.com/alecthomas/kong"
)

// TODO: memory limit
// TODO: cgroup
// TODO: namespaces

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)

	switch ctx.Command() {
	case "run <args>":
		if cli.Run.Config == "" {
			helpUsage()
		}

		run(cli)
	case "exec <args>":
		if cli.Exec.Config == "" {
			helpUsage()
		}

		config, err := util.LoadConfig(cli.Exec.Config)
		util.Bail(err)

		restrict.EnforceLandlock(config.Landlock)
		restrict.SetRlimits(config.Rlimits)
		restrict.PrivelegeDrop(config.Uid, config.Gid)
		restrict.EnforceSeccomp(config.Seccomp)

		executable := cli.Exec.Args[0]
		child(executable, cli.Exec.Args[1:])
	default:
		helpUsage()
	}
}

func run(cli CLI) {
	arguments := []string{"exec", "--config", cli.Run.Config}
	arguments = append(arguments, cli.Run.Args...)
	cmd := exec.Command("/proc/self/exe", arguments...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	/*
				config, err := util.LoadConfig(cli.Run.Config)
				util.Bail(err)

		    cmd.SysProcAttr = &syscall.SysProcAttr{
		      GidMappings: []syscall.SysProcIDMap{
		        {
		          ContainerID: config.Gid,
		          HostID:      config.Gid,
		          Size:        1,
		        },
		      },
		      UidMappings: []syscall.SysProcIDMap{
		        {
		          ContainerID: config.Uid,
		          HostID:      config.Uid,
		          Size:        1,
		        },
		      },
		    }
	*/

	cmd.Run()

	if !cmd.ProcessState.Exited() {
		wt := cmd.ProcessState.Sys().(syscall.WaitStatus)
		if wt.Signaled() {
			fmt.Println(wt.Signal())
		}
	}
}

func child(executable string, args []string) {
	cmd := exec.Command(executable, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// FIXME: why mapping using SysProcAttr did not work?
	// uid 0 (host) -> 1000 (container)
	// gid 0 (host) -> 1000 (container)
	cmd.Run()

	procState := cmd.ProcessState
	usage, ok := procState.SysUsage().(*syscall.Rusage)
	if !ok {
		util.MessageBail("failed to get usage")
	}

	metrics := model.Metrics{
		ExitCode: procState.ExitCode(),
		UserTime: time.Duration(usage.Utime.Nano()), // ns
		SysTime:  time.Duration(usage.Stime.Nano()), // ns
		Memory:   usage.Maxrss,                      // kb
	}

	if !procState.Exited() {
		wt := procState.Sys().(syscall.WaitStatus)
		if wt.Signaled() {
			metrics.Signal = wt.Signal()
		}
	}

	result := model.Result{
		Success: true,
		Metric:  metrics,
		Stdout:  stdout.String(),
		Stderr:  stderr.String(),
	}

	marshaled, err := json.Marshal(result)
	util.Bail(err)

	fmt.Println(string(marshaled))
}

func helpUsage() {
	fmt.Fprintln(os.Stderr, "usage:\nkaleng run --config config.json executable arguments")
	os.Exit(0)
}

type CLI struct {
	Run struct {
		Config string
		Args   []string `arg:""`
	} `cmd:""`

	Exec struct {
		Config string
		Args   []string `arg:""`
	} `cmd:""`
}
