// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

// Package http_dialer provides HTTP(S) CONNECT tunneling net.Dialer. It allows you to
// establish arbitrary TCP connections (as long as your proxy allows them) through a HTTP(S) CONNECT point.
package http_dialer

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type opt func(*HttpTunnel)

// New constructs an HttpTunnel to be used a net.Dial command.
// The first parameter is a proxy URL, for example https://foo.example.com:9090 will use foo.example.com as proxy on
// port 9090 using TLS for connectivity.
// Optional customization parameters are available, e.g.: WithTls, WithContextDialer, WithConnectionTimeout
func New(proxyUrl *url.URL, opts ...opt) *HttpTunnel {
	t := &HttpTunnel{
		parentDialer: &net.Dialer{},
	}
	t.parseProxyUrl(proxyUrl)
	for _, opt := range opts {
		opt(t)
	}
	return t
}

// WithTls sets the tls.Config to be used (e.g. CA certs) when connecting to an HTTP proxy over TLS.
func WithTls(tlsConfig *tls.Config) opt {
	return func(t *HttpTunnel) {
		t.tlsConfig = tlsConfig
	}
}

// WithContextDialer allows the customization of the underlying ContextDialer used to establish TCP connections to the proxy.
func WithContextDialer(dialer ContextDialer) opt {
	return func(t *HttpTunnel) {
		t.parentDialer = dialer
	}
}

// WithConnectionTimeout customizes the underlying net.Dialer.Timeout.
// If underlying dialer is not net.Dialer, this call has no effect.
func WithConnectionTimeout(timeout time.Duration) opt {
	return func(t *HttpTunnel) {
		netDialer, ok := t.parentDialer.(*net.Dialer)
		if ok {
			netDialer.Timeout = timeout
		}
		return
	}
}

// WithProxyAuth allows you to add ProxyAuthorization to calls.
func WithProxyAuth(auth ProxyAuthorization) opt {
	return func(t *HttpTunnel) {
		t.auth = auth
	}
}

// HttpTunnel represents a configured HTTP Connect Tunnel dialer.
type HttpTunnel struct {
	parentDialer ContextDialer
	isTls        bool
	proxyAddr    string
	tlsConfig    *tls.Config
	auth         ProxyAuthorization
}

func (t *HttpTunnel) parseProxyUrl(proxyUrl *url.URL) {
	t.proxyAddr = proxyUrl.Host
	if strings.ToLower(proxyUrl.Scheme) == "https" {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":443"
		}
		t.isTls = true
	} else {
		if !strings.Contains(t.proxyAddr, ":") {
			t.proxyAddr = t.proxyAddr + ":8080"
		}
		t.isTls = false
	}
}

func (t *HttpTunnel) dialProxyContext(ctx context.Context) (net.Conn, error) {
	if !t.isTls {
		return t.parentDialer.DialContext(ctx, "tcp", t.proxyAddr)
	}
	conn, err := t.parentDialer.DialContext(ctx, "tcp", t.proxyAddr)
	if err != nil {
		return nil, err
	}
	c := t.tlsConfig
	if c == nil || (c.ServerName == "" && !c.InsecureSkipVerify) {
		serverName, _, err := net.SplitHostPort(t.proxyAddr)
		if err != nil {
			return nil, err
		}
		c.ServerName = serverName
	}
	return tls.Client(conn, c), nil
}

// Dial is a DialContext call with context.Background
func (t *HttpTunnel) Dial(network string, addr string) (net.Conn, error) {
	return t.DialContext(context.Background(), network, addr)
}

// DialContext is an implementation of ContextDialer, and returns a TCP connection handle to the host that HTTP CONNECT reached.
// Connection lifecycle is controlled by ctx.
func (t *HttpTunnel) DialContext(ctx context.Context, network string, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("network type '%v' unsupported (only 'tcp')", network)
	}
	conn, err := t.dialProxyContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("http_tunnel: failed dialing to proxy: %v", err)
	}
	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address, // This is weird
		Header: make(http.Header),
	}
	req = req.WithContext(ctx)
	if t.auth != nil && t.auth.InitialResponse() != "" {
		req.Header.Set(hdrProxyAuthResp, t.auth.Type()+" "+t.auth.InitialResponse())
	}
	resp, err := t.doRoundtrip(conn, req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	// Retry request with auth, if available.
	if resp.StatusCode == http.StatusProxyAuthRequired && t.auth != nil {
		responseHdr, err := t.performAuthChallengeResponse(resp)
		if err != nil {
			conn.Close()
			return nil, err
		}
		req.Header.Set(hdrProxyAuthResp, t.auth.Type()+" "+responseHdr)
		resp, err = t.doRoundtrip(conn, req)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("http_tunnel: failed proxying %d: %s", resp.StatusCode, resp.Status)
	}
	return conn, nil
}

func (t *HttpTunnel) doRoundtrip(conn net.Conn, req *http.Request) (*http.Response, error) {
	if err := req.Write(conn); err != nil {
		return nil, fmt.Errorf("http_tunnel: failed writing request: %v", err)
	}
	// Doesn't matter, discard this bufio.
	br := bufio.NewReader(conn)
	return http.ReadResponse(br, req)

}

func (t *HttpTunnel) performAuthChallengeResponse(resp *http.Response) (string, error) {
	respAuthHdr := resp.Header.Get(hdrProxyAuthReq)
	if !strings.Contains(respAuthHdr, t.auth.Type()+" ") {
		return "", fmt.Errorf("http_tunnel: expected '%v' Proxy authentication, got: '%v'", t.auth.Type(), respAuthHdr)
	}
	splits := strings.SplitN(respAuthHdr, " ", 2)
	challenge := splits[1]
	return t.auth.ChallengeResponse(challenge), nil
}
