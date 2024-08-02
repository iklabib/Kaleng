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
	"github.com/docker/docker/pkg/reexec"
)

// TODO: cgroup
// TODO: better landlock violation report

func main() {
	var cli CLI
	ctx := kong.Parse(&cli)

	config, err := util.LoadConfig(cli.Execute.Config)
	util.Bail(err)

	if cli.Execute.Config == "" {
		helpUsage(ctx.Model.Help)
	}

	args := append([]string{"setup"}, os.Args[1:]...)
	cmd := reexec.Command(args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	sysProcAttr := &syscall.SysProcAttr{
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
		sysProcAttr.Cloneflags = restrict.GetNamespaceFlag(config.Namespaces)
	}

	cmd.SysProcAttr = sysProcAttr

	err = cmd.Start()
	util.Bail(err)

	err = cmd.Wait()
	util.Bail(err)
}

func init() {
	reexec.Register("setup", setup)
	if reexec.Init() {
		os.Exit(0)
	}
}

func setup() {
	var cli CLI
	kong.Parse(&cli)

	config, err := util.LoadConfig(cli.Execute.Config)
	util.Bail(err)

	restrict.SetEnvs(config.Envs)
	restrict.PivotRoot(cli.Execute.Root, cli.Execute.Rootfs)

	// restrict.SetRlimits(config.Rlimits)
	// restrict.EnforceLandlock(config.Landlock)
	restrict.EnforceSeccomp(config.Seccomp)

	executable := cli.Execute.Args[0]
	args := cli.Execute.Args[1:]

	execute(executable, args)
}

func execute(executable string, args []string) {
	cmd := exec.Command(executable, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Stdin = os.Stdin

	util.Bail(cmd.Start())

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

	switch metrics.Signal {
	// SIGSYS likely caused by seccomp violation
	case syscall.SIGSYS:
		result.Message = "restriction violated"
	}

	marshaled, err := json.Marshal(result)
	util.Bail(err)

	fmt.Println(string(marshaled))
}

func helpUsage(help string) {
	fmt.Fprintln(os.Stderr, help)
	os.Exit(0)
}

type CLI struct {
	Execute struct {
		Config string
		Root   string
		Rootfs string
		Args   []string `arg:"" passthrough:""`
	} `cmd:""`
}
