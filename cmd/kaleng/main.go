package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"codeberg.org/iklabib/kaleng/configs"
	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/restrict"
	"codeberg.org/iklabib/kaleng/util"
	"codeberg.org/iklabib/kaleng/util/reexec"
	"github.com/alecthomas/kong"
)

// TODO: better cgroup violation report
// TODO: better landlock violation report
// TODO: kill all cgroup process except for the init process

func main() {
	var cli CLI
	kong.Parse(&cli)

	buf, err := io.ReadAll(os.Stdin)
	util.Bail(err)

	config, err := restrict.LoadConfigFromStdin(buf)
	util.Bail(err)

	restrict.PreChroot(cli.Execute.Root, cli.Execute.Rootfs)

	args := append([]string{"setup"}, os.Args[1:]...)
	cmd := reexec.Command(args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = bytes.NewReader(buf)

	cg := restrict.CGroup(cli.Execute.Root, config.Cgroup)
	sysProcAttr := &syscall.SysProcAttr{
		Chroot:                     cli.Execute.Root,
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
		UseCgroupFD: true,
		CgroupFD:    cg.GetFD(),
		Cloneflags:  restrict.GetNamespaceFlag(config.Namespaces),
	}

	cmd.SysProcAttr = sysProcAttr

	err = cmd.Start()
	util.Bail(err)

	cmd.Wait()

	util.Bail(cg.CloseFd())

	cgroupViolations, err := cg.Violations()
	util.Bail(err)

	if len(cgroupViolations) == 0 {
		fmt.Print(stdout.String())
	} else {
		var result model.Result
		err = json.Unmarshal(stdout.Bytes(), &result)
		util.Bail(err)
		result.Message = append(result.Message, cgroupViolations...)

		content, err := json.Marshal(result)
		util.Bail(err)

		fmt.Println(string(content))
	}

	restrict.CleanChroot(cli.Execute.Root)
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

	var config configs.KalengConfig
	buf, err := io.ReadAll(os.Stdin)
	util.Bail(err)

	config, err = restrict.LoadConfigFromStdin(buf)
	util.Bail(err)

	restrict.SetEnvs(config.Envs)
	restrict.SetRlimits(config.Rlimits)
	restrict.EnforceLandlock(config.Files)
	restrict.EnforceSeccomp(config.Seccomp)

	executable := cli.Execute.Args[0]
	args := cli.Execute.Args[1:]

	execute(executable, args, config)
}

func execute(executable string, args []string, config configs.KalengConfig) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(config.TimeLimit)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

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

	result := model.Result{
		Metric: metrics,
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			result.Message = append(result.Message, "time limit exceeded")
		} else if errors.Is(err, context.Canceled) {
			result.Message = append(result.Message, "canceled")
		}
	}

	if !procState.Exited() {
		wt := procState.Sys().(syscall.WaitStatus)
		if wt.Signaled() {
			metrics.Signal = wt.Signal()
		}
	}

	// SIGSYS likely caused by seccomp violation
	if metrics.Signal == syscall.SIGSYS {
		result.Message = append(result.Message, "security restriction violated")
	}

	marshaled, err := json.Marshal(result)
	util.Bail(err)

	fmt.Println(string(marshaled))

	os.Exit(procState.ExitCode())
}

func helpUsage(help string) {
	fmt.Fprintln(os.Stderr, help)
	os.Exit(0)
}

type CLI struct {
	Execute struct {
		Root   string
		Rootfs string
		Args   []string `arg:"" passthrough:""`
	} `cmd:""`
}
