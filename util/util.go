package util

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"codeberg.org/iklabib/kaleng/model"
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
