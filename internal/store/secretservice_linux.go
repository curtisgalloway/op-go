// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

package store

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

const secretBus = "org.freedesktop.secrets"
const secretRoot = dbus.ObjectPath("/org/freedesktop/secrets")

type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

func nativeOperation(ctx context.Context, req request) (result response, resultErr error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			result = response{}
			resultErr = err
		}
	}()
	if err := ctx.Err(); err != nil {
		return response{}, err
	}
	if req.Backend != "secret-service" {
		return response{}, ErrUnavailable
	}
	// Avoid godbus's dbus-launch fallback and remote transports. This source
	// requires an existing local session bus, never an auto-launched daemon.
	address := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if address == "" {
		address = "unix:path=/run/user/" + strconv.Itoa(os.Geteuid()) + "/bus"
	}
	if !strings.HasPrefix(address, "unix:") || strings.Contains(address, ";") {
		return response{}, ErrUnavailable
	}
	conn, err := dbus.Connect(address, dbus.WithContext(ctx))
	if err != nil {
		return response{}, ErrUnavailable
	}
	defer conn.Close()
	call := func(path dbus.ObjectPath, method string, args ...any) *dbus.Call {
		return conn.Object(secretBus, path).CallWithContext(ctx, method, 0, args...)
	}
	var collection dbus.ObjectPath
	if err = call(secretRoot, "org.freedesktop.Secret.Service.ReadAlias", "default").Store(&collection); err != nil {
		return response{}, dbusError(err)
	}
	if collection == "/" {
		return response{}, ErrUnavailable
	}
	locked := func(path dbus.ObjectPath, iface string) error {
		var value dbus.Variant
		if err := call(path, "org.freedesktop.DBus.Properties.Get", iface, "Locked").Store(&value); err != nil {
			return dbusError(err)
		}
		flag, ok := value.Value().(bool)
		if !ok {
			return ErrUnavailable
		}
		if flag {
			return ErrLocked
		}
		return nil
	}
	if err = locked(collection, "org.freedesktop.Secret.Collection"); err != nil {
		return response{}, err
	}
	attrs := map[string]string{"service": "op-go", "account": "service-account"}
	var items []dbus.ObjectPath
	if err = call(collection, "org.freedesktop.Secret.Collection.SearchItems", attrs).Store(&items); err != nil {
		return response{}, dbusError(err)
	}
	if len(items) > 1 {
		return response{}, ErrDenied
	}
	if len(items) == 1 {
		if err = locked(items[0], "org.freedesktop.Secret.Item"); err != nil {
			return response{}, err
		}
	}
	switch req.Operation {
	case "status":
		return response{Present: len(items) == 1}, nil
	case "delete":
		if len(items) == 0 {
			return response{}, ErrNotFound
		}
		var prompt dbus.ObjectPath
		if err = call(items[0], "org.freedesktop.Secret.Item.Delete").Store(&prompt); err != nil {
			return response{}, mutationDBusError(err)
		}
		if prompt != "/" {
			return response{}, ErrLocked
		}
		return response{}, nil
	case "read", "write":
	default:
		return response{}, ErrDenied
	}
	if req.Operation == "read" && len(items) == 0 {
		return response{}, ErrNotFound
	}
	if req.Operation == "write" && len(items) > 0 && !req.Replace {
		return response{}, ErrExists
	}
	// The plain session uses the authenticated local session bus. Same-user bus
	// inspection is outside the threat model; no token enters argv or environment.
	var output dbus.Variant
	var session dbus.ObjectPath
	if err = call(secretRoot, "org.freedesktop.Secret.Service.OpenSession", "plain", dbus.MakeVariant("")).Store(&output, &session); err != nil {
		return response{}, dbusError(err)
	}
	defer call(session, "org.freedesktop.Secret.Session.Close")
	if req.Operation == "read" {
		var value secret
		if err = call(items[0], "org.freedesktop.Secret.Item.GetSecret", session).Store(&value); err != nil {
			return response{}, dbusError(err)
		}
		if value.Session != session || len(value.Parameters) != 0 {
			return response{}, ErrDenied
		}
		token, err := NormalizeToken(string(value.Value))
		return response{Token: token}, err
	}
	token, err := NormalizeToken(req.Token)
	if err != nil {
		return response{}, err
	}
	value := secret{session, []byte{}, []byte(token), "text/plain; charset=utf-8"}
	properties := map[string]dbus.Variant{"org.freedesktop.Secret.Item.Label": dbus.MakeVariant("op-go service account"), "org.freedesktop.Secret.Item.Attributes": dbus.MakeVariant(attrs)}
	var item, prompt dbus.ObjectPath
	// Replace=false lets the service create; existing items were checked above.
	if err = call(collection, "org.freedesktop.Secret.Collection.CreateItem", properties, value, req.Replace).Store(&item, &prompt); err != nil {
		return response{}, mutationDBusError(err)
	}
	if prompt != "/" {
		return response{}, ErrLocked
	}
	if item == "/" {
		return response{}, ErrUnavailable
	}
	return response{}, nil
}

func mutationDBusError(err error) error {
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if safe := dbusError(err); safe != ErrUnavailable {
		return safe
	}
	// The service may have committed a mutation before its reply was lost.
	return ErrOutcomeUnknown
}

func dbusError(err error) error {
	if e, ok := err.(dbus.Error); ok {
		switch {
		case strings.HasSuffix(e.Name, ".IsLocked"):
			return ErrLocked
		case strings.HasSuffix(e.Name, ".NoSuchObject"):
			return ErrNotFound
		case strings.HasSuffix(e.Name, ".AccessDenied"):
			return ErrDenied
		}
	}
	return ErrUnavailable
}
