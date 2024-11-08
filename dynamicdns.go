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
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/libdns/libdns"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(App{})
}

// App is a Caddy app that keeps your DNS records updated with the public
// IP address of your instance. It updates A and AAAA records.
type App struct {
	// The configuration for the DNS provider with which the DNS
	// records will be updated.
	DNSProviderRaw json.RawMessage `json:"dns_provider,omitempty" caddy:"namespace=dns.providers inline_key=name"`

	dnsProvider interface {
		libdns.RecordGetter
		libdns.RecordSetter
		libdns.RecordAppender
	}

	// The record names, keyed by DNS zone, for which to update the A/AAAA records.
	// Record names are relative to the zone. The zone is usually your registered
	// domain name. To refer to the zone itself, use the record name of "@".
	//
	// For example, assuming your zone is example.com, and you want to update A/AAAA
	// records for "example.com" and "www.example.com" so that they resolve to this
	// Caddy instance, configure like so: `"example.com": ["@", "www"]`
	Domains map[string][]string `json:"domains,omitempty"`

	// If enabled, no new DNS records will be created. Only existing records will be updated.
	// This means that the A or AAAA records need to be created manually ahead of time.
	UpdateOnly bool `json:"update_only,omitempty"`

	// How frequently to check the public IP address. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The TTL to set on DNS records. Default: 600s
	TTL caddy.Duration `json:"ttl,omitempty"`

	// The sources from which to get the server's public IP address.
	// Multiple sources can be specified for redundancy.
	// Default: simple_http
	IPv4SourcesRaw []json.RawMessage `json:"ipv4_sources,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`
	IPv6SourcesRaw []json.RawMessage `json:"ipv6_sources,omitempty" caddy:"namespace=dynamic_dns.ip_sources inline_key=source"`

	ipv4Sources []IPSource
	ipv6Sources []IPSource

	ctx    caddy.Context
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns",
		New: func() caddy.Module { return new(App) },
	}
}

// Provision sets up the app module.
func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger(a)

	// set up the DNS provider module
	if len(a.DNSProviderRaw) == 0 {
		return fmt.Errorf("a DNS provider is required")
	}
	val, err := ctx.LoadModule(a, "DNSProviderRaw")
	if err != nil {
		return fmt.Errorf("loading DNS provider module: %v", err)
	}
	a.dnsProvider = val.(interface {
		libdns.RecordGetter
		libdns.RecordSetter
		libdns.RecordAppender
	})

	// set up the IP source module or use a default
	vals, err := ctx.LoadModule(a, "IPv4SourcesRaw")
	if err != nil {
		return fmt.Errorf("loading IPv4 source module: %v", err)
	}
	for _, val := range vals.([]interface{}) {
		a.ipv4Sources = append(a.ipv4Sources, val.(IPSource))
	}

	vals, err = ctx.LoadModule(a, "IPv6SourcesRaw")
	if err != nil {
		return fmt.Errorf("loading IPv6 source module: %v", err)
	}
	for _, val := range vals.([]interface{}) {
		a.ipv6Sources = append(a.ipv6Sources, val.(IPSource))
	}

	// make sure a check interval is set
	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(defaultCheckInterval)
	}

	if a.TTL == 0 {
		a.TTL = caddy.Duration(defaultTTL)
	}

	if time.Duration(a.CheckInterval) < time.Second {
		return fmt.Errorf("check interval must be at least 1 second")
	}

	return nil
}

// Start starts the app module.
func (a App) Start() error {
	go a.checkerLoop()
	return nil
}

// Stop stops the app module.
func (a App) Stop() error {
	return nil
}

// checkerLoop checks the public IP address at every check
// interval. It stops when a.ctx is cancelled.
func (a App) checkerLoop() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()

	a.checkIPAndUpdateDNS()

	for {
		select {
		case <-ticker.C:
			a.checkIPAndUpdateDNS()
		case <-a.ctx.Done():
			return
		}
	}
}

// checkIPAndUpdateDNS checks public IP addresses and, for any IP addresses
// that are different from before, it updates DNS records accordingly.
func (a *App) checkIPAndUpdateDNS() {
	a.logger.Debug("beginning IP address check")

	// get ipv4 address from first successful IP source
	a.logger.Info("IPv4 sources", zap.Any("sources", a.ipv4Sources))

	var ipv4 net.IP
	for _, ipSrc := range a.ipv4Sources {
		a.logger.Info("looking up IPv4 address by source", zap.String("source", ipSrc.(caddy.Module).CaddyModule().ID.Name()))
		ip, err := ipSrc.GetIP(a.ctx, IPv4Version)
		if err != nil {
			continue
		}

		ipv4 = ip
		a.logger.Info("found IPv4 address", zap.String("address", ipv4.String()))
		break
	}

	// get ipv6 address from first successful IP source
	a.logger.Info("IPv6 sources", zap.Any("sources", a.ipv6Sources))
	var ipv6 net.IP
	for _, ipSrc := range a.ipv6Sources {
		a.logger.Info("looking up IPv6 address by source", zap.String("source", ipSrc.(caddy.Module).CaddyModule().ID.Name()))
		ip, err := ipSrc.GetIP(a.ctx, IPv6Version)
		if err != nil {
			continue
		}

		ipv6 = ip
		a.logger.Info("found IPv6 address", zap.String("address", ipv6.String()))
		break
	}

	// if none of the sources returned an IP address, log an error and return
	if ipv4 == nil && ipv6 == nil {
		a.logger.Error("no IP addresses found")
		return
	}

	// do a diff of current and previous IPs to make DNS records to update
	for zone, names := range a.Domains {
		// find all records for the zone
		remoteRecords, err := a.dnsProvider.GetRecords(a.ctx, zone)
		if err != nil {
			a.logger.Error("failed to get all records for zone", zap.String("zone", zone), zap.Error(err))
			continue
		}

		needAppendRecords := make(map[string][]libdns.Record)
		needUpdateRecords := make(map[string][]libdns.Record)
		for _, name := range names {
			processRecord := func(recordType string, ip net.IP) {
				var record libdns.Record
				for _, r := range remoteRecords {
					if r.Name == name && r.Type == recordType {
						record = r
						break
					}
				}

				if record.Name == "" {
					if a.UpdateOnly {
						a.logger.Error("record doesn't exist; skipping update",
							zap.String("zone", zone),
							zap.String("name", name),
							zap.String("type", recordType),
						)
						return
					}

					needAppendRecords[zone] = append(needAppendRecords[zone], libdns.Record{
						Type:  recordType,
						Name:  name,
						Value: ip.String(),
						TTL:   time.Duration(a.TTL),
					})
					return
				}

				if record.Value == ip.String() {
					// IP is not different and no new domains to manage; no update needed
					return
				}

				needUpdateRecords[zone] = append(needUpdateRecords[zone], libdns.Record{
					ID:    record.ID,
					Type:  recordType,
					Name:  record.Name,
					Value: ip.String(),
					TTL:   time.Duration(a.TTL),
				})
			}

			if ipv4 != nil {
				processRecord(recordTypeA, ipv4)
			}
			if ipv6 != nil {
				processRecord(recordTypeAAAA, ipv6)
			}
		}

		if len(needAppendRecords) > 0 {
			for _, rec := range needAppendRecords[zone] {
				a.logger.Info("appending DNS record",
					zap.String("zone", zone),
					zap.String("name", rec.Name),
					zap.String("type", rec.Type),
					zap.String("value", rec.Value),
				)
			}
			_, err = a.dnsProvider.AppendRecords(a.ctx, zone, needAppendRecords[zone])
			if err != nil {
				a.logger.Error("failed to append DNS record(s)", zap.String("zone", zone), zap.Error(err))
			}
		}

		if len(needUpdateRecords) > 0 {
			for _, rec := range needUpdateRecords[zone] {
				a.logger.Info("updating DNS record",
					zap.String("id", rec.ID),
					zap.String("zone", zone),
					zap.String("name", rec.Name),
					zap.String("type", rec.Type),
					zap.String("value", rec.Value),
				)
			}
			_, err = a.dnsProvider.SetRecords(a.ctx, zone, needUpdateRecords[zone])
			if err != nil {
				a.logger.Error("failed to update DNS record(s)", zap.String("zone", zone), zap.Error(err))
			}
		}
	}

	a.logger.Info("finished updating DNS")
}

const (
	recordTypeA    = "A"
	recordTypeAAAA = "AAAA"
)

const defaultCheckInterval = 30 * time.Minute
const defaultTTL = 600 * time.Second

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
