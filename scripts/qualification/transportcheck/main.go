// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

// Credential-free transport diagnosis against a disposable, trusted TLS server.
// It preserves Go's default ten-second TLS handshake timeout and uses httptrace
// to distinguish completed TLS/request writes from a stalled TLS handshake.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

func main() {
	proxyURL := flag.String("proxy", "", "local qualification proxy")
	deadline := flag.Duration("deadline", 30*time.Second, "request deadline")
	flag.Parse()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer server.Close()
	json.NewEncoder(os.Stdout).Encode(map[string]int{"port": server.Listener.Addr().(*net.TCPAddr).Port})
	if !bufio.NewScanner(os.Stdin).Scan() {
		os.Exit(2)
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	proxy, err := url.Parse(*proxyURL)
	if err != nil {
		os.Exit(2)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: server.Certificate().DNSNames[0]}
	defer transport.CloseIdleConnections()
	var tlsDone, wroteRequest atomic.Bool
	trace := &httptrace.ClientTrace{
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) { tlsDone.Store(err == nil) },
		WroteRequest:     func(info httptrace.WroteRequestInfo) { wroteRequest.Store(info.Err == nil) },
	}
	ctx, cancel := context.WithTimeout(httptrace.WithClientTrace(context.Background(), trace), *deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://test.1password.com/", nil)
	if err != nil {
		os.Exit(2)
	}
	start := time.Now()
	response, err := (&http.Client{Transport: transport}).Do(req)
	if response != nil {
		response.Body.Close()
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{
		"success": err == nil, "tls_verified": tlsDone.Load(), "request_written": wroteRequest.Load(),
		"context_expired": ctx.Err() != nil, "seconds": time.Since(start).Seconds(),
		"transport_handshake_timeout_seconds": transport.TLSHandshakeTimeout.Seconds(),
	})
}
