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
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("dynamic_dns", parseApp)
}

// parseApp configures the "dynamic_dns" global option from Caddyfile.
// Syntax:
//
//	dynamic_dns {
//		provider <name> ...
//		domains {
//			<zone> <names...>
//		}
//		ipv4 {
//			ip_source simple_http <endpoint>
//		}
//		ipv6 {
//			ip_source interface <interface>
//		}
//		update_only
//		check_interval <duration>
//		ttl <duration>
//	}
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
func parseApp(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(App)

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	// handle the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "domains":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				zone := d.Val()
				if zone == "" {
					return nil, d.ArgErr()
				}
				names := d.RemainingArgs()
				if len(names) == 0 {
					names = []string{"@"}
				}
				if app.Domains == nil {
					app.Domains = make(map[string][]string)
				}
				app.Domains[zone] = append(app.Domains[zone], names...)
			}

		case "update_only":
			if d.NextArg() {
				return nil, d.ArgErr()
			}
			app.UpdateOnly = true

		case "check_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.CheckInterval = caddy.Duration(dur)

		case "provider":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			provName := d.Val()
			modID := "dns.providers." + provName
			unm, err := caddyfile.UnmarshalModule(d, modID)
			if err != nil {
				return nil, err
			}
			app.DNSProviderRaw = caddyconfig.JSONModuleObject(unm, "name", provName, nil)

		case "ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.TTL = caddy.Duration(dur)

		case "ipv4":
			if d.NextArg() {
				return nil, d.ArgErr()
			}

			ipv4Nesting := d.Nesting()
			for d.NextBlock(ipv4Nesting) {
				switch d.Val() {
				case "ip_source":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sourceType := d.Val()
					modID := "dynamic_dns.ip_sources." + sourceType
					unm, err := caddyfile.UnmarshalModule(d, modID)
					if err != nil {
						return nil, err
					}
					app.IPv4SourcesRaw = append(app.IPv4SourcesRaw, caddyconfig.JSONModuleObject(unm, "source", sourceType, nil))
				}
			}

		case "ipv6":
			if d.NextArg() {
				return nil, d.ArgErr()
			}

			ipv6Nesting := d.Nesting()
			for d.NextBlock(ipv6Nesting) {
				switch d.Val() {
				case "ip_source":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					sourceType := d.Val()
					modID := "dynamic_dns.ip_sources." + sourceType
					unm, err := caddyfile.UnmarshalModule(d, modID)
					if err != nil {
						return nil, err
					}
					app.IPv6SourcesRaw = append(app.IPv6SourcesRaw, caddyconfig.JSONModuleObject(unm, "source", sourceType, nil))
				}
			}

		default:
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
