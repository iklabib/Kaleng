package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/util/fastrand"
	"github.com/elastic/go-ucfg/yaml"
)

func LoadConfig(path string) (model.KalengConfig, error) {
	var config model.KalengConfig

	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			MessageBail("config file does not exist")
		} else {
			MessageBail("failed to check config file")
		}
	}

	// yaml is super set of json anyway
	cfg, err := yaml.NewConfigWithFile(path)
	if err != nil {
		return config, err
	}

	if err := cfg.Unpack(&config); err != nil {
		return config, err
	}

	return config, nil
}

var INTERNAL_ERROR = -1

func Bail(err error) {
	if err != nil {
		format := "{\"stdout\":\"\",\"stderr\":\"\",\"message\":\"%v\",\"metric\":{\"signal\":null,\"exit_code\":-1,\"sys_time\":0,\"time\":0}\n"
		fmt.Printf(format, err)
		os.Exit(INTERNAL_ERROR)
	}
}

func MessageBail(msg string) {
	format := "{\"stdout\":\"\",\"stderr\":\"\",\"message\":\"%s\",\"metric\":{\"signal\":null,\"exit_code\":-1,\"sys_time\":0,\"time\":0}\n"
	fmt.Printf(format, msg)
	os.Exit(INTERNAL_ERROR)
}

func MountProc(path string) {
	procPath := filepath.Join(path, "proc")

	// ignore if dir exist
	if err := os.Mkdir(procPath, 0o555); !os.IsExist(err) {
		Bail(err)
	}

	var mountFlags uintptr = syscall.MS_REC | syscall.MS_BIND | syscall.MS_PRIVATE
	err := syscall.Mount("/proc", procPath, "procfs", mountFlags, "")
	Bail(err)
}

func CopyRootFs(source, target string) {
	if err := CopyDirectory(source, target); err != nil {
		Bail(fmt.Errorf("rootfs copy failed: %s", err.Error()))
	}
}

var devices = map[string]os.FileMode{
	"/dev/null":    0o666,
	"/dev/zero":    0o666,
	"/dev/full":    0o666,
	"/dev/urandom": 0o444,
}

func MountBindDev(path string) {
	for dev, mode := range devices {
		target := filepath.Join(path, dev)
		f, err := os.Create(target)
		Bail(err)
		defer f.Close()

		Bail(os.Chmod(target, mode))

		err = syscall.Mount(dev, target, "", syscall.MS_BIND, "")
		if err != nil {
			MessageBail(fmt.Sprintf("device: failed to bind %s to %s %v", dev, target, err))
		}
	}

	// create shm
	err := os.Mkdir(filepath.Join(path, "/dev/shm"), 0o1777)
	if err != nil {
		MessageBail(fmt.Sprintf("device: failed to create /dev/shm %v", err))
	}
}

func UnmoutProc(path string) {
	procPath := filepath.Join(path, "proc")
	err := syscall.Unmount(procPath, syscall.MNT_DETACH)
	Bail(err)
}

func UnmoutDev(path string) {
	for dev := range devices {
		devPath := filepath.Join(path, dev)
		err := syscall.Unmount(devPath, syscall.MNT_DETACH)
		if err != nil {
			MessageBail(fmt.Sprintf("device: failed to unmount %s %v", dev, err))
		}
	}

	// create shm
	err := os.RemoveAll(filepath.Join(path, "/dev/shm"))
	if err != nil {
		MessageBail(fmt.Sprintf("device: failed to remove /dev/shm %v", err))
	}
}

func CreateTmpfs(path string) {
	err := syscall.Mount("tmpfs", path, "tmpfs", 0, "size=128M,mode=755")
	if err != nil {
		Bail(fmt.Errorf("failed to create tmpfs: %s", err.Error()))
	}
}

func RandomNumber(n uint32) uint32 {
	if n == 0 {
		return fastrand.Uint32()
	}

	return fastrand.Uint32n(n)
}
