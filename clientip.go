package seamlessauth

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

const maxUserAgentLength = 512

// TrustedProxies returns a ResolveClientIP for an app behind proxies with these
// addresses or subnets ("10.0.0.0/8", "127.0.0.1"). It walks X-Forwarded-For from
// the right, skipping trusted proxies, and returns the first address that is not
// one. There is deliberately no hop count: it cannot tell a proxy from a client
// that sent its own header.
func TrustedProxies(proxies ...string) func(*http.Request) string {
	var prefixes []netip.Prefix
	for _, p := range proxies {
		if prefix, err := netip.ParsePrefix(p); err == nil {
			prefixes = append(prefixes, prefix.Masked())
		} else if addr, err := netip.ParseAddr(p); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	trusted := func(s string) bool {
		addr, err := netip.ParseAddr(strings.TrimSpace(s))
		if err != nil {
			return false
		}
		addr = addr.Unmap()
		for _, p := range prefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}

	return func(r *http.Request) string {
		peer := remoteHost(r)
		if !trusted(peer) {
			return peer
		}

		var hops []string
		for _, header := range r.Header.Values("X-Forwarded-For") {
			for _, hop := range strings.Split(header, ",") {
				if hop = strings.TrimSpace(hop); hop != "" {
					hops = append(hops, hop)
				}
			}
		}

		for i := len(hops) - 1; i >= 0; i-- {
			if !trusted(hops[i]) {
				return hops[i]
			}
		}
		if len(hops) > 0 {
			return hops[0]
		}
		return peer
	}
}

func remoteHost(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *Adapter) clientIP(r *http.Request) string {
	candidate := remoteHost(r)
	if a.opts.ResolveClientIP != nil {
		candidate = a.opts.ResolveClientIP(r)
	}
	if addr, err := netip.ParseAddr(candidate); err == nil {
		return addr.Unmap().String()
	}
	return ""
}

func clientUserAgent(r *http.Request) string {
	ua := strings.TrimSpace(r.UserAgent())
	if len(ua) > maxUserAgentLength {
		ua = ua[:maxUserAgentLength]
	}
	return ua
}
