// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SimpleHTTP{})
	caddy.RegisterModule(NetInterface{})
	caddy.RegisterModule(Static{})
}

// IPSource is a type that can get IP addresses.
type IPSource interface {
	GetIP(context.Context, IPVersion) (net.IP, error)
}

// SimpleHTTP is an IP source that looks up the public IP addresses by
// making HTTP(S) requests to the specified endpoints; it will try each
// endpoint with IPv4 and IPv6 until at least one returns a valid value.
// It is OK if an endpoint doesn't support both IP versions; returning
// a single valid IP address is sufficient.
//
// The endpoints must return HTTP status 200 and the response body must
// contain only the IP address in plain text.
type SimpleHTTP struct {
	// The list of endpoints to query. If empty, a default list will
	// be used:
	//
	// - https://icanhazip.com
	// - https://ifconfig.me
	// - https://ident.me
	// - https://ipecho.net/plain
	Endpoints []string `json:"endpoints,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (SimpleHTTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.simple_http",
		New: func() caddy.Module { return new(SimpleHTTP) },
	}
}

func (sh *SimpleHTTP) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	var (
		unused   string
		endpoint string
	)
	if !d.AllArgs(&unused, &endpoint) {
		return d.ArgErr()
	}
	sh.Endpoints = append(sh.Endpoints, endpoint)
	return nil
}

// Provision sets up the module.
func (sh *SimpleHTTP) Provision(ctx caddy.Context) error {
	sh.logger = ctx.Logger(sh)
	if len(sh.Endpoints) == 0 {
		sh.Endpoints = defaultHTTPIPServices
	}
	return nil
}

// GetIP gets the public addresses of this machine.
func (sh SimpleHTTP) GetIP(ctx context.Context, version IPVersion) (net.IP, error) {
	getForVersion := func(network string, name string) net.IP {
		client := sh.makeClient(network)
		for _, endpoint := range sh.Endpoints {
			ip, err := sh.lookupIP(ctx, client, endpoint)
			if err != nil {
				sh.logger.Debug("lookup failed",
					zap.String("type", name),
					zap.String("endpoint", endpoint),
					zap.Error(err))
				continue
			}
			sh.logger.Debug("lookup",
				zap.String("type", name),
				zap.String("endpoint", endpoint),
				zap.String("ip", ip.String()))
			return ip
		}
		sh.logger.Warn("no IP found for %s", zap.String("type", name))
		return nil
	}

	switch version {
	case IPv4Version:
		ip := getForVersion("tcp4", "IPv4")
		if ip != nil {
			return ip, nil
		}
	case IPv6Version:
		ip := getForVersion("tcp6", "IPv6")
		if ip != nil {
			return ip, nil
		}
	default:
		return nil, fmt.Errorf("invalid IP version: %d", version)
	}

	return nil, fmt.Errorf("no IP found")
}

// makeClient makes an HTTP client that forces use of the specified network type (e.g. "tcp6").
func (SimpleHTTP) makeClient(network string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, address)
			},
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

func (SimpleHTTP) lookupIP(ctx context.Context, client *http.Client, endpoint string) (net.IP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: server response was: %d %s", endpoint, resp.StatusCode, resp.Status)
	}

	ipASCII, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return nil, err
	}
	ipStr := strings.TrimSpace(string(ipASCII))

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("%s: invalid IP address: %s", endpoint, ipStr)
	}

	return ip, nil
}

var defaultHTTPIPServices = []string{
	"https://icanhazip.com",
	"https://ifconfig.me",
	"https://ident.me",
	"https://ipecho.net/plain",
}

// NetInterface gets the public IP address(es) (at most 1 IPv4 and 1 IPv6) from a network interface by name.
type NetInterface struct {
	// The name of the network interface.
	Name string `json:"name,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (NetInterface) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.interface",
		New: func() caddy.Module { return new(NetInterface) },
	}
}

func (u *NetInterface) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // skip directive name
	if !d.NextArg() {
		return d.ArgErr()
	}
	u.Name = d.Val()
	return nil
}

// Provision sets up the module.
func (u *NetInterface) Provision(ctx caddy.Context) error {
	u.logger = ctx.Logger(u)
	return nil
}

// GetIP gets the public address of from the network interface.
func (u NetInterface) GetIP(ctx context.Context, version IPVersion) (net.IP, error) {
	iface, err := net.InterfaceByName(u.Name)
	if err != nil {
		return nil, fmt.Errorf("couldn't find interface '%s': %v", u.Name, err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("couldn't load addresses for interface '%s': %v", u.Name, err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() || ipNet.IP.IsPrivate() || !ipNet.IP.IsGlobalUnicast() {
			continue
		}

		switch version {
		case IPv4Version:
			if ipNet.IP.To4() != nil {
				return ipNet.IP, nil
			}
		case IPv6Version:
			if ipNet.IP.To16() != nil {
				return ipNet.IP, nil
			}
		default:
			return nil, fmt.Errorf("invalid IP version: %d", version)
		}
	}

	return nil, fmt.Errorf("no IP found")
}

type Static struct {
	IP net.IP `json:"ip,omitempty"`

	logger *zap.Logger
}

func (Static) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns.ip_sources.static",
		New: func() caddy.Module { return new(Static) },
	}
}

func (s Static) GetIP(ctx context.Context, version IPVersion) (net.IP, error) {
	switch version {
	case IPv4Version:
		if s.IP.To4() != nil {
			return s.IP, nil
		}
	case IPv6Version:
		if s.IP.To16() != nil {
			return s.IP, nil
		}
	default:
		return nil, fmt.Errorf("invalid IP version: %d", version)
	}

	return nil, fmt.Errorf("no IP found")
}

func (s *Static) Provision(ctx caddy.Context) error {
	s.logger = ctx.Logger(s)

	if s.IP == nil {
		s.logger.Warn("No static IPs configured")
	}

	return nil
}

func (s *Static) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // skip directive name

	for d.NextArg() {
		raw_ip := d.Val()
		ip := net.ParseIP(raw_ip)
		if ip == nil {
			return d.Errf("Invalid IP address: %v", raw_ip)
		}

		s.IP = ip
	}

	return nil
}

// Interface guards
var (
	_ IPSource              = (*SimpleHTTP)(nil)
	_ caddy.Provisioner     = (*SimpleHTTP)(nil)
	_ caddyfile.Unmarshaler = (*SimpleHTTP)(nil)

	_ IPSource              = (*NetInterface)(nil)
	_ caddy.Provisioner     = (*NetInterface)(nil)
	_ caddyfile.Unmarshaler = (*NetInterface)(nil)

	_ IPSource              = (*Static)(nil)
	_ caddy.Provisioner     = (*Static)(nil)
	_ caddyfile.Unmarshaler = (*Static)(nil)
)

type IPVersion int

const (
	IPv4Version IPVersion = iota
	IPv6Version
)
