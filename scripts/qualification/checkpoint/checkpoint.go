// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Package checkpoint is opt-in qualification instrumentation, never imported by
// the release CLI. It blocks at named phases until the local observer inspects
// arguments/environments; it never receives credentials.
package checkpoint

import (
	"encoding/json"
	"net"
	"os"
	"time"
)

func Hit(phase string) { Child(phase, 0) }

func Child(phase string, child int) {
	path := os.Getenv("OP_GO_QUALIFICATION_SOCKET")
	if path == "" {
		return
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		os.Exit(90)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if json.NewEncoder(c).Encode(struct {
		Phase string
		PID   int
		Child int
	}{phase, os.Getpid(), child}) != nil {
		os.Exit(90)
	}
	var ack [1]byte
	if _, err := c.Read(ack[:]); err != nil || ack[0] != 1 {
		os.Exit(90)
	}
}
