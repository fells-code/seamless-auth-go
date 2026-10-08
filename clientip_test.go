package seamlessauth

import (
	"net/http/httptest"
	"testing"
)

func TestTrustedProxies(t *testing.T) {
	resolve := TrustedProxies("10.0.0.0/8", "127.0.0.1")

	cases := []struct {
		name, peer, forwarded, want string
	}{
		{"no proxy", "203.0.113.9:1", "", "203.0.113.9"},
		{"an untrusted peer cannot set its own address", "203.0.113.9:1", "6.6.6.6", "203.0.113.9"},
		{"behind a trusted proxy", "10.0.0.5:1", "203.0.113.50", "203.0.113.50"},
		{"a spoofed entry left of the real client is ignored", "10.0.0.5:1", "6.6.6.6, 203.0.113.50", "203.0.113.50"},
		{"through two trusted proxies", "127.0.0.1:1", "203.0.113.51, 10.0.0.7", "203.0.113.51"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = c.peer
			if c.forwarded != "" {
				req.Header.Set("X-Forwarded-For", c.forwarded)
			}
			if got := resolve(req); got != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
}
