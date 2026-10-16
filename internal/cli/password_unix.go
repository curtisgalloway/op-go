//go:build darwin || linux

// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

// Restore echo even if an SSH session disconnects or the user interrupts input.
func readTerminalPassword(fd int) ([]byte, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	stopped := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer func() {
		signal.Stop(signals)
		close(done)
		<-stopped
	}()
	defer term.Restore(fd, state)
	go func() {
		defer close(stopped)
		select {
		case sig := <-signals:
			_ = term.Restore(fd, state)
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig.(syscall.Signal))
		case <-done:
		}
	}()
	return term.ReadPassword(fd)
}
