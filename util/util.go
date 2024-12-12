package util

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"

	"codeberg.org/iklabib/kaleng/configs"
	"codeberg.org/iklabib/kaleng/model"
	"codeberg.org/iklabib/kaleng/util/fastrand"
)

func Bail(err error) {
	if err != nil {
		MessageBail(err.Error())
	}
}

func MessageBail(msg string) {
	res := model.Result{
		Output: msg,
		Metric: model.Metrics{ExitCode: -1},
	}
	v, _ := json.Marshal(res)
	fmt.Println(string(v))
	runtime.Goexit()
}

func MountProc(path string) {
	procPath := filepath.Join(path, "proc")

	// ignore if dir exist
	if err := os.Mkdir(procPath, 0o555); !os.IsExist(err) {
		Bail(err)
	}

	var mountFlags uintptr = syscall.MS_REC | syscall.MS_BIND | syscall.MS_PRIVATE
	err := syscall.Mount("/proc", procPath, "procfs", mountFlags, "remount,hidepid=2")
	Bail(err)
}

func BindMount(parent string, bind configs.Bind) {
	target := filepath.Join(parent, bind.Target)
	var flags uintptr = syscall.MS_BIND | syscall.MS_NODEV | syscall.MS_PRIVATE | syscall.MS_NOSUID
	err := syscall.Mount(bind.Source, target, bind.FsType, flags, bind.Data)
	if err != nil {
		Bail(fmt.Errorf("failed to bind mount %s %s", bind.Source, err.Error()))
	}
}

func BindUnmount(target string) {
	err := syscall.Unmount(target, syscall.MNT_DETACH)
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
	os.Mkdir(filepath.Join(path, "dev"), 0o751)

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

func UnmountCGroup(path string) {
	procPath := filepath.Join(path, "sys/fs/cgroup")
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

func MountMnt(path string, size uint) {
	tmpPath := filepath.Join(path, "tmp")
	os.MkdirAll(tmpPath, 0o777)
	var flags uintptr = syscall.MS_NODEV | syscall.MS_NOSUID | syscall.MS_NOSUID
	data := fmt.Sprintf("size=%d,mode=1777", size)
	err := syscall.Mount("tmpfs", tmpPath, "tmpfs", flags, data)
	Bail(err)
}

func MountCGroupV2(path string) {
	cgroupRoot := filepath.Join(path, "sys", "fs", "cgroup")
	Bail(os.MkdirAll(cgroupRoot, 0o777))
	var flags uintptr = syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC
	err := syscall.Mount("cgroup", cgroupRoot, "cgroup2", flags, "")
	Bail(err)
}

func RandomNumber(n uint32) uint32 {
	if n == 0 {
		return fastrand.Uint32()
	}

	return fastrand.Uint32n(n)
}

func LookupUser(username string) int {
	user, err := user.Lookup(username)
	Bail(err)

	uid, err := strconv.Atoi(user.Uid)
	Bail(err)

	return uid
}

func LookupGroup(group string) int {
	user, err := user.LookupGroup(group)
	Bail(err)

	gid, err := strconv.Atoi(user.Gid)
	Bail(err)

	return gid
}
