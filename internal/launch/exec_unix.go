// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package launch

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"strconv"
)

func replace(path string, args, env []string) error {
	// Go opens its own descriptors close-on-exec. Also cover descriptors inherited
	// from callers and native adapters rather than trusting their flags.
	dir := "/dev/fd"
	if runtime.GOOS == "linux" {
		dir = "/proc/self/fd"
	}
	// List names only. os.ReadDir may stat each entry, and on macOS the runtime's
	// network-poller kqueue is listed in /dev/fd but cannot be stat'ed (EBADF).
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	names, err := d.Readdirnames(-1)
	d.Close()
	if err != nil {
		return err
	}
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			continue
		} // Directory descriptor is already closed.
		if err != nil {
			return err
		}
		_, err = unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC)
		if err != nil && !errors.Is(err, unix.EBADF) {
			return err
		}
	}
	return unix.Exec(path, args, env)
}
