Dynamic DNS app for Caddy
=========================

This is a simple Caddy app that keeps your DNS pointed to your machine; especially useful if your IP address is not static.

It simply queries a service (an "IP source") for your public IP address every so often and if it changes, it updates the DNS records with your configured provider. It supports multiple IPs, including IPv4 and IPv6, as well as redundant IP sources.

IP sources and DNS providers are modular. This app comes with IP source modules. However, you'll need to plug in [a DNS provider module from caddy-dns](https://github.com/caddy-dns) so that your DNS records can be updated.

### Caddyfile Example

```
{
	dynamic_dns {
		provider tencentcloud {
			secret_id mysecret
			secret_key mykey
		}

		domains {
			example.com www
		}

		ipv4 {
			ip_source simple_http https://icanhazip.com
			ip_source simple_http https://ifconfig.me
		}

		ipv6 {
			ip_source interface eth0
		}

		ttl 600s
		check_interval 30m

		# update_only # if set, only existing records will be updated
	}
}
```
