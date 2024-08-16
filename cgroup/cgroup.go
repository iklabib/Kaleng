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

type CGroup struct {
	name     string
	controls map[string]bool
	fullPath string
	fd       int
}

type MemoryEvents struct {
	Low          int
	High         int
	Max          int
	Oom          int
	OomKill      int
	OomGroupKill int
}

func New(name string) (*CGroup, error) {
	dir := filepath.Join(cgroupRoot, name)

	if err := os.Mkdir(dir, 0o744); err != nil {
		err = fmt.Errorf("failed to create new cgroup %s", err.Error())
		return nil, err
	}

	cg, err := LoadGroup(name)
	if err != nil {
		return nil, err
	}

	return cg, nil
}

func LoadGroup(name string) (*CGroup, error) {
	dir := filepath.Join(cgroupRoot, name)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil, err
	}

	controls, err := availableControls(dir)
	if err != nil {
		return nil, err
	}

	if len(controls) == 0 {
		return nil, fmt.Errorf("no controllers available")
	}

	cg := CGroup{
		name:     name,
		fullPath: dir,
		controls: map[string]bool{},
	}

	// https://github.com/golang/go/blob/master/src/syscall/exec_linux_test.go
	const O_PATH = 0x200000
	fd, err := syscall.Open(cg.fullPath, O_PATH, 0)
	if err != nil {
		return nil, err
	}

	cg.fd = fd

	for _, ctl := range controls {
		cg.controls[ctl] = true
	}

	return &cg, nil
}

func (cg *CGroup) SetCpu(cpu configs.Cpu) {
	if cpu.Weight > 0 {
		err := cg.setControl("cpu.weight", fmt.Sprintf("%d", cpu.Weight))
		util.Bail(err)
	}

	if cpu.Time > 0 && cpu.Period > 0 {
		err := cg.setControl("cpu.max", fmt.Sprintf("%d %d", cpu.Time, cpu.Period))
		util.Bail(err)
	}
}

func (cg *CGroup) SetMaximumPids(lim int) {
	// no-op
	if lim == 0 {
		return
	}
	err := cg.setControl("pids.max", fmt.Sprintf("%d", lim))
	util.Bail(err)
}

func (cg *CGroup) SetMaximumMemory(lim string) {
	// no-op
	if lim == "" {
		return
	}

	err := cg.setControl("memory.max", lim)
	util.Bail(err)

	err = cg.setControl("memory.oom.group", "1")
	util.Bail(err)
}

func (cg *CGroup) AddPid(pid int) error {
	return cg.write("cgroup.procs", strconv.Itoa(pid))
}

func (cg *CGroup) IsControlAvailable(name string) bool {
	return cg.controls[name]
}

func (cg *CGroup) AddControl(ctl string) error {
	if !cg.IsControlAvailable(ctl) {
		return fmt.Errorf("unavailable control %s", ctl)
	}

	return cg.writeSubTreeControl("+" + ctl)
}

func (cg *CGroup) RemoveControl(ctl string) error {
	if !cg.IsControlAvailable(ctl) {
		return fmt.Errorf("unavailable control %s", ctl)
	}

	return cg.writeSubTreeControl("-" + ctl)
}

func (cg *CGroup) setControl(name, lim string) error {
	ctl := filepath.Join(cg.fullPath, name)
	if _, err := os.Stat(ctl); os.IsNotExist(err) {
		return fmt.Errorf("invalid control %s", name)
	}

	return cg.write(name, lim)
}

func (cg *CGroup) writeSubTreeControl(ctl string) error {
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

func (cg *CGroup) DisableSwap() error {
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

func (cg *CGroup) SetMaximumDescendants(lim int) {
	// no-op
	if lim == 0 {
		return
	}

	err := cg.setControl("cgroup.max.descendants", strconv.Itoa(lim))
	util.Bail(err)
}

func (cg *CGroup) SetMaximumDepth(lim int) {
	// no-op
	if lim == 0 {
		return
	}

	err := cg.setControl("cgroup.max.depth", strconv.Itoa(lim))
	util.Bail(err)
}

func (cg *CGroup) GetFD() int {
	return cg.fd
}

func (cg *CGroup) CloseFd() error {
	return syscall.Close(cg.fd)
}

func (cg *CGroup) Kill() error {
	return cg.write("cgroup.kill", "1")
}

func (cg *CGroup) write(name, lim string) error {
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

func (cg *CGroup) PidsEvents() (int, error) {
	path := filepath.Join(cg.fullPath, "pids.events")
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	trimmed := strings.TrimLeft(string(content), "max ")
	trimmed = strings.TrimSpace(trimmed)

	return strconv.Atoi(trimmed)
}

func (cg *CGroup) OomEvents() (MemoryEvents, error) {
	path := filepath.Join(cg.fullPath, "memory.events")
	content, err := os.ReadFile(path)
	if err != nil {
		return MemoryEvents{}, err
	}

	memEvents := MemoryEvents{}
	trimmed := strings.TrimSpace(string(content))
	for _, line := range strings.Split(trimmed, "\n") {
		segments := strings.Split(line, " ")
		key := segments[0]
		val, err := strconv.Atoi(segments[1])
		if err != nil {
			return memEvents, err
		}

		switch key {
		case "low":
			memEvents.Low = val
		case "high":
			memEvents.High = val
		case "max":
			memEvents.Max = val
		case "oom":
			memEvents.Oom = val
		case "oom_kill":
			memEvents.OomKill = val
		case "oom_group_kill":
			memEvents.OomGroupKill = val
		default:
			return memEvents, fmt.Errorf("unknown key %s", key)
		}
	}

	return memEvents, nil
}

// check for cgroup violations
func (cg *CGroup) Violations() []string {
	var violations []string

	if pidsEvents, err := cg.PidsEvents(); err != nil {
		util.Bail(err)
	} else if pidsEvents > 0 {
		violations = append(violations, "maximum pids restriction violated")
	}

	if oomEvents, err := cg.OomEvents(); err != nil {
		util.Bail(err)
	} else if oomEvents.Oom > 0 || oomEvents.OomKill > 0 || oomEvents.OomGroupKill > 0 {
		violations = append(violations, "memory restriction violated")
	}

	return violations
}

func DeleteGroup(name string) error {
	path := filepath.Join(cgroupRoot, name)
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("failed to delete cgroup group %s %v", name, err)
	}
	return nil
}
