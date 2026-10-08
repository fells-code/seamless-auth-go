package seamlessauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"
)

// A kid the cached key set does not know triggers at most one refetch per this
// interval, so a stream of forged kids cannot turn into a stream of fetches.
const jwksRefetchInterval = 30 * time.Second

type jwksCache struct {
	url    string
	client *http.Client

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

func newJWKSCache(authServerURL string, client *http.Client) *jwksCache {
	return &jwksCache{url: authServerURL + "/.well-known/jwks.json", client: client}
}

func (c *jwksCache) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	if c.keys != nil && time.Since(c.fetchedAt) < jwksRefetchInterval {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	if err := c.fetch(ctx); err != nil {
		return nil, err
	}
	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("unknown key id %q", kid)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (c *jwksCache) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", res.StatusCode)
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&set); err != nil {
		return err
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		n, err := b64.DecodeString(k.N)
		if err != nil {
			continue
		}
		e, err := b64.DecodeString(k.E)
		if err != nil || len(e) > 4 {
			continue
		}
		exponent := 0
		for _, b := range e {
			exponent = exponent<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent}
	}

	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

// verifyAuthToken checks a token the auth API signed: RS256 under a key it
// publishes, issued by issuer for audience, and in date.
func (c *jwksCache) verifyAuthToken(ctx context.Context, token, issuer, audience string) (map[string]any, error) {
	parsed, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	key, err := c.key(ctx, parsed.header.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyRS256(parsed, key); err != nil {
		return nil, err
	}
	if stringClaim(parsed.claims, "iss") != issuer {
		return nil, errors.New("unexpected issuer")
	}
	if !audienceMatches(parsed.claims, audience) {
		return nil, errors.New("unexpected audience")
	}
	if err := checkTimes(parsed.claims, time.Now()); err != nil {
		return nil, err
	}
	return parsed.claims, nil
}
