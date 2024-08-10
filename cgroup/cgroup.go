package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"codeberg.org/iklabib/kaleng/configs"
	"codeberg.org/iklabib/kaleng/util"
)

var cgroupRoot string = "/sys/fs/cgroup"

type cgroup struct {
	name     string
	controls map[string]bool
	fullPath string
	proc     *os.File
}

func New(name string) (*cgroup, error) {
	dir := filepath.Join(cgroupRoot, name)

	if err := os.Mkdir(dir, 0o744); err != nil {
		err = fmt.Errorf("failed to create new cgroup %s", err.Error())
		return nil, err
	}

	controls, err := availableControls(dir)
	if err != nil {
		return nil, err
	}

	if len(controls) == 0 {
		return nil, fmt.Errorf("no controllers available")
	}

	cg := cgroup{
		name:     name,
		fullPath: dir,
		controls: map[string]bool{},
	}

	for _, ctl := range controls {
		cg.controls[ctl] = true
	}

	return &cg, nil
}

func (cg *cgroup) SetCpu(cpu configs.Cpu) {
	if cpu.Weight > 0 {
		err := cg.SetControl("cpu.weight", fmt.Sprintf("%d", cpu.Weight))
		util.Bail(err)
	}

	if cpu.Time > 0 && cpu.Period > 0 {
		err := cg.SetControl("cpu.max", fmt.Sprintf("%d %d", cpu.Time, cpu.Period))
		util.Bail(err)
	}
}

func (cg *cgroup) SetMaximumProcs(lim int) {
	err := cg.SetControl("pids.max", fmt.Sprintf("%d", lim))
	util.Bail(err)
}

func (cg *cgroup) SetMaximumMemory(lim string) {
	err := cg.SetControl("memory.max", lim)
	util.Bail(err)
}

func (cg *cgroup) AddPid(pid int) error {
	return cg.write("cgroup.procs", strconv.Itoa(pid))
}

func (cg *cgroup) IsControlAvailable(name string) bool {
	return cg.controls[name]
}

func (cg *cgroup) AddControl(ctl string) error {
	if !cg.IsControlAvailable(ctl) {
		return fmt.Errorf("unavailable control %s", ctl)
	}

	return cg.writeSubTreeControl("+" + ctl)
}

func (cg *cgroup) RemoveControl(ctl string) error {
	if !cg.IsControlAvailable(ctl) {
		return fmt.Errorf("unavailable control %s", ctl)
	}

	return cg.writeSubTreeControl("-" + ctl)
}

func (cg *cgroup) SetControl(name, lim string) error {
	ctl := filepath.Join(cg.fullPath, name)
	if _, err := os.Stat(ctl); os.IsNotExist(err) {
		return fmt.Errorf("invalid control %s", name)
	}

	return cg.write(name, lim)
}

func (cg *cgroup) writeSubTreeControl(ctl string) error {
	subTreeCtlPath := filepath.Join(cg.fullPath, "cgroup.subtree_control")
	subTreeCtl, err := os.OpenFile(subTreeCtlPath, syscall.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer subTreeCtl.Close()

	_, err = subTreeCtl.Write([]byte(ctl))
	if err != nil {
		return err
	}

	return nil
}

func (cg *cgroup) DisableSwap() error {
	// disable swap
	if err := cg.write("memory.swap.max", "0"); err != nil {
		return err
	}

	// disable zswap
	if err := cg.write("memory.zswap.max", "0"); err != nil {
		return err
	}

	return nil
}

func (cg *cgroup) GetFD() (int, error) {
	if cg.proc != nil {
		return int(cg.proc.Fd()), nil
	}

	procs := filepath.Join(cg.fullPath, "cgroup.controllers")
	f, err := os.Open(procs)
	if err != nil {
		return 0, err
	}
	cg.proc = f

	return int(cg.proc.Fd()), nil
}

func (cg *cgroup) Kill() error {
	return cg.write("cgroup.kill", "1")
}

func (cg *cgroup) write(name, lim string) error {
	path := filepath.Join(cg.fullPath, name)
	// no-op when does not exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	return os.WriteFile(path, []byte(lim), 0o644)
}

func availableControls(path string) ([]string, error) {
	ctl := filepath.Join(path, "cgroup.controllers")
	rawBytes, err := os.ReadFile(ctl)
	if err != nil {
		return nil, err
	}

	controllers := strings.Split(string(rawBytes), " ")
	return controllers, nil
}
