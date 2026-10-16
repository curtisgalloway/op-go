// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"bytes"
	"context"
	"encoding/xml"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

const gnomeUnlockInterface = "org.gnome.keyring.InternalUnsupportedGuiltRiddenInterface"

// GNOME's password extension addresses an existing collection directly. The
// standard Secret Service Unlock method may open a graphical prompt instead.
// This extension is not a stable API: check its signature before taking input.
func unlockOperation(ctx context.Context, req request) (resultErr error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			resultErr = err
		}
	}()
	if req.Backend != "secret-service" {
		return ErrUnavailable
	}
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if address == "" {
		address = "unix:path=/run/user/" + strconv.Itoa(os.Geteuid()) + "/bus"
	}
	if !strings.HasPrefix(address, "unix:") || strings.Contains(address, ";") {
		return ErrUnavailable
	}
	conn, err := dbus.Connect(address, dbus.WithContext(ctx))
	if err != nil {
		return ErrUnavailable
	}
	defer conn.Close()
	var owner, gnomeOwner string
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, secretBus).Store(&owner); err != nil {
		return dbusError(err)
	}
	if err = conn.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.GetNameOwner", 0, "org.gnome.keyring").Store(&gnomeOwner); err != nil {
		return dbusError(err)
	}
	if owner != gnomeOwner {
		return ErrUnavailable
	}
	obj := conn.Object(owner, secretRoot)
	var collection, login dbus.ObjectPath
	if err = obj.CallWithContext(ctx, "org.freedesktop.Secret.Service.ReadAlias", 0, "default").Store(&collection); err != nil {
		return dbusError(err)
	}
	if err = obj.CallWithContext(ctx, "org.freedesktop.Secret.Service.ReadAlias", 0, "login").Store(&login); err != nil {
		return dbusError(err)
	}
	if login == "/" || login != collection {
		return ErrUnavailable
	}
	var description string
	if err = obj.CallWithContext(ctx, "org.freedesktop.DBus.Introspectable.Introspect", 0).Store(&description); err != nil {
		return dbusError(err)
	}
	if !hasPasswordUnlock(description) {
		return ErrUnavailable
	}
	if req.Operation == "unlock-check" {
		return nil
	}
	if req.Operation != "unlock" {
		return ErrDenied
	}
	if len(req.Password) == 0 || len(req.Password) > maxToken || bytes.IndexByte(req.Password, 0) >= 0 {
		return ErrInvalidFile
	}
	var output dbus.Variant
	var session dbus.ObjectPath
	if err = obj.CallWithContext(ctx, "org.freedesktop.Secret.Service.OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return dbusError(err)
	}
	defer conn.Object(owner, session).CallWithContext(ctx, "org.freedesktop.Secret.Session.Close", 0)
	value := secret{session, []byte{}, req.Password, "text/plain; charset=utf-8"}
	if err = obj.CallWithContext(ctx, gnomeUnlockInterface+".UnlockWithMasterPassword", 0, collection, value).Err; err != nil {
		if e, ok := err.(dbus.Error); ok && (e.Name == "org.freedesktop.Secret.Error.IsLocked" || e.Name == "org.gnome.keyring.Error.Denied") {
			return ErrLocked
		}
		return dbusError(err)
	}
	var locked dbus.Variant
	if err = conn.Object(owner, collection).CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, "org.freedesktop.Secret.Collection", "Locked").Store(&locked); err != nil {
		return dbusError(err)
	}
	flag, ok := locked.Value().(bool)
	if !ok {
		return ErrUnavailable
	}
	if flag {
		return ErrLocked
	}
	return nil
}

func hasPasswordUnlock(description string) bool {
	if len(description) > 64*1024 {
		return false
	}
	var node introspect.Node
	if xml.Unmarshal([]byte(description), &node) != nil {
		return false
	}
	for _, iface := range node.Interfaces {
		if iface.Name != gnomeUnlockInterface {
			continue
		}
		for _, method := range iface.Methods {
			if method.Name != "UnlockWithMasterPassword" || len(method.Args) != 2 {
				continue
			}
			if method.Args[0].Type != "o" || method.Args[1].Type != "(oayays)" {
				continue
			}
			if (method.Args[0].Direction == "" || method.Args[0].Direction == "in") && (method.Args[1].Direction == "" || method.Args[1].Direction == "in") {
				return true
			}
		}
	}
	return false
}
