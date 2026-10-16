// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPasswordSignalHelper(t *testing.T) {
	if os.Getenv("OP_GO_TEST_PASSWORD_HELPER") != "1" {
		return
	}
	_, err := readTerminalPassword(int(os.Stdin.Fd()))
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestPasswordSignalsRestoreEcho(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			if err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
				t.Fatal(err)
			}
			number, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
			if err != nil {
				t.Fatal(err)
			}
			slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|syscall.O_NOCTTY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer slave.Close()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestPasswordSignalHelper$")
			cmd.Env = append(os.Environ(), "OP_GO_TEST_PASSWORD_HELPER=1")
			cmd.Stdin = slave
			var output bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &output
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if cmd.ProcessState == nil {
					cmd.Process.Kill()
					cmd.Wait()
				}
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
				if err != nil {
					t.Fatal(err)
				}
				if state.Lflag&unix.ECHO == 0 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("hidden input did not start")
				}
				time.Sleep(time.Millisecond)
			}
			if err = cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			finished := make(chan error, 1)
			go func() { finished <- cmd.Wait() }()
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				cmd.Process.Kill()
				<-finished
				t.Fatal("signal did not terminate password reader")
			}
			status := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !status.Signaled() || status.Signal() != sig {
				t.Fatalf("wrong signal status: %v", status)
			}
			state, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
			if err != nil || state.Lflag&unix.ECHO == 0 {
				t.Fatal("terminal echo not restored")
			}
		})
	}
}
