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

// TODO: cgroup

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

		restrict.SetEnvs(config.Envs)
		restrict.EnforceLandlock(config.Landlock)
		restrict.SetRlimits(config.Rlimits)
		restrict.EnforceSeccomp(config.Seccomp)

		executable := cli.Exec.Args[0]
		child(executable, cli.Exec.Args[1:])
	default:
		helpUsage()
	}
}

func run(cli CLI) {
	config, err := util.LoadConfig(cli.Run.Config)
	util.Bail(err)

	procAttr := syscall.SysProcAttr{
		GidMappingsEnableSetgroups: true,
		UidMappings: []syscall.SysProcIDMap{
			{
				HostID:      os.Getuid(),
				ContainerID: config.Uid,
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				HostID:      os.Getgid(),
				ContainerID: config.Gid,
				Size:        1,
			},
		},
	}

	// only apply namespaces if flags provided
	if len(config.Namespaces) > 0 {
		procAttr.Cloneflags = restrict.GetNamespaceFlag(config.Namespaces)
	}

	arguments := []string{"exec", "--config", cli.Run.Config}
	arguments = append(arguments, cli.Run.Args...)
	cmd := exec.Command("/proc/self/exe", arguments...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.SysProcAttr = &procAttr
	cmd.Run()
}

func child(executable string, args []string) {
	cmd := exec.Command(executable, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Start(); err != nil {
		util.Bail(err)
	}

	cmd.Wait()

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
		Metric: metrics,
		Stdout: stdout.String(),
		Stderr: stderr.String(),
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
		Args   []string `arg:"" passthrough:""`
	} `cmd:""`

	Exec struct {
		Config string
		Args   []string `arg:"" passthrough:""`
	} `cmd:""`
}
