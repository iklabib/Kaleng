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

func main() {
	defer os.Exit(0)
	var cli CLI
	kong.Parse(&cli)

	buf, err := os.ReadFile(cli.Execute.Config)
	util.Bail(err)

	config, err := restrict.Config(buf)
	util.Bail(err)

	restrict.PreChroot(cli.Execute.Root, config.Binds)

	stdout, violations := execSetup(cli.Execute.Root, bytes.NewBuffer(buf), config)
	defer restrict.CleanChroot(cli.Execute.Root, config.Binds)

	if len(violations) == 0 {
		fmt.Print(stdout.String())
	} else {
		var result model.Result
		err = json.Unmarshal(stdout.Bytes(), &result)
		util.Bail(err)

		result.Message = append(result.Message, violations...)

		content, err := json.Marshal(result)
		util.Bail(err)

		fmt.Println(string(content))
	}
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

	config := restrict.Setup()
	executable := cli.Execute.Args[0]
	args := cli.Execute.Args[1:]

	execute(executable, args, config.TimeLimit)
}

func execute(executable string, args []string, timeLimit int) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeLimit)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable, args...)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output

	start := time.Now()
	util.Bail(cmd.Start())

	cmd.Wait()
	wallTime := time.Since(start)

	procState := cmd.ProcessState
	usage, ok := procState.SysUsage().(*syscall.Rusage)
	if !ok {
		util.MessageBail("failed to get usage")
	}

	metrics := model.Metrics{
		WallTime: wallTime,
		ExitCode: procState.ExitCode(),
		UserTime: time.Duration(usage.Utime.Nano()), // ns
		SysTime:  time.Duration(usage.Stime.Nano()), // ns
		Memory:   usage.Maxrss,                      // kb
	}

	result := model.Result{
		Metric: metrics,
		Output: output.String(),
	}

	if err := ctx.Err(); err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			result.Message = append(result.Message, "time limit exceeded")
		} else if errors.Is(err, context.Canceled) {
			result.Message = append(result.Message, "canceled")
		} else {
			result.Message = append(result.Message, err.Error())
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

func execSetup(root string, stdin io.Reader, config configs.KalengConfig) (bytes.Buffer, []string) {
	cg := restrict.CGroup(root, config.Cgroup)
	defer cg.CloseFd()

	uid := util.LookupUser(config.User)
	gid := util.LookupGroup(config.Group)

	args := append([]string{"setup"}, os.Args[1:]...)
	cmd := reexec.Command(args...)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stdin = stdin
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Chroot:                     root,
		GidMappingsEnableSetgroups: true,
		UidMappings: []syscall.SysProcIDMap{
			{
				HostID:      os.Getuid(),
				ContainerID: uid,
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				HostID:      os.Getgid(),
				ContainerID: gid,
				Size:        1,
			},
		},
		UseCgroupFD: true,
		CgroupFD:    cg.GetFD(),
		Cloneflags:  restrict.GetNamespaceFlag(config.Namespaces),
	}

	util.Bail(cmd.Start())
	cmd.Wait()

	return stdout, cg.Violations()
}

type CLI struct {
	Execute struct {
		Root   string
		Config string
		Args   []string `arg:"" passthrough:""`
	} `cmd:""`
}
