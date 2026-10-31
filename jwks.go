package seamlessauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

const (
	// A kid the cached key set does not know triggers at most one refetch per this
	// interval, so a stream of forged kids cannot turn into a stream of fetches.
	jwksRefetchInterval = 30 * time.Second
	// A key set older than this is fetched again, so a key the API retires stops
	// verifying.
	jwksMaxAge = 10 * time.Minute
	// With no key set at all, how long a failed fetch holds off the next.
	jwksFailureBackoff = 5 * time.Second
	jwksFetchTimeout   = 5 * time.Second
	maxJWKSBytes       = 256 << 10
)

type jwksCache struct {
	url    string
	client *http.Client
	logf   func(string, ...any)

	mu          sync.Mutex
	keys        map[string]publishedKey
	fetchedAt   time.Time
	attemptedAt time.Time
}

// publishedKey is an RSA key from a key set, with the use and alg members it was
// published with, raw so that a member of the wrong type stays visible.
type publishedKey struct {
	pub *rsa.PublicKey
	use json.RawMessage
	alg json.RawMessage
}

func newJWKSCache(url string, client *http.Client, logf func(string, ...any)) *jwksCache {
	return &jwksCache{url: url, client: client, logf: logf}
}

func (c *jwksCache) key(ctx context.Context, kid string) (publishedKey, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	fresh := !c.fetchedAt.IsZero() && now.Sub(c.fetchedAt) < jwksMaxAge
	if key, ok := c.keys[kid]; ok && fresh {
		return key, nil
	}

	backoff := jwksFailureBackoff
	if c.keys != nil {
		backoff = jwksRefetchInterval
	}
	if c.attemptedAt.IsZero() || now.Sub(c.attemptedAt) >= backoff {
		c.attemptedAt = now
		if err := c.fetch(ctx); err != nil {
			if c.keys == nil {
				return publishedKey{}, err
			}
			// A stale key set keeps verifying while the API cannot be reached,
			// rather than signing every user out.
			c.logf("[seamless-auth] Could not refresh the JWKS (%v).", err)
		}
	}

	if key, ok := c.keys[kid]; ok {
		return key, nil
	}
	return publishedKey{}, fmt.Errorf("unknown key id %q", kid)
}

type jwk struct {
	Kty string          `json:"kty"`
	Kid string          `json:"kid"`
	N   string          `json:"n"`
	E   string          `json:"e"`
	Use json.RawMessage `json:"use"`
	Alg json.RawMessage `json:"alg"`
}

func (c *jwksCache) fetch(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return err
	}
	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("jwks: %w", upstreamError(err))
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: HTTP %d", res.StatusCode)
	}
	if res.ContentLength > maxJWKSBytes {
		return errors.New("jwks: response too large")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("jwks: %w", upstreamError(err))
	}
	if len(data) > maxJWKSBytes {
		return errors.New("jwks: response too large")
	}

	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return err
	}

	keys := make(map[string]publishedKey, len(set.Keys))
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
		keys[k.Kid] = publishedKey{
			pub: &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exponent},
			use: k.Use,
			alg: k.Alg,
		}
	}

	c.keys = keys
	c.fetchedAt = time.Now()
	return nil
}

// verifyAuthToken checks a token the auth API signed: RS256 under a key it
// publishes, issued by issuer for audience, and in date.
func (c *jwksCache) verifyAuthToken(ctx context.Context, token, issuer, audience string) (map[string]any, error) {
	// An empty expectation would match a token that omits the claim.
	if issuer == "" || audience == "" {
		return nil, errors.New("no expected issuer or audience")
	}
	parsed, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	key, err := c.key(ctx, parsed.header.Kid)
	if err != nil {
		return nil, err
	}
	if err := verifyRS256(parsed, key.pub); err != nil {
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
