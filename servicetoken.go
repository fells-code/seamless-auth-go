package seamlessauth

import (
	"sync"
	"time"
)

// The auth API validates service tokens against a fixed issuer and audience,
// whatever the adopter's own audience is.
const (
	serviceTokenIssuer   = "seamless-portal-api"
	serviceTokenAudience = "seamless-auth"
	serviceTokenTTL      = 60 * time.Second
	proxyTokenSubject    = "seamless-auth-go-adapter"
	deliveryTokenSubject = "seamless-auth-external-delivery"
	// Reused for a little less than its lifetime, so a request never signs a fresh
	// token and never presents one that expires in flight.
	proxyTokenReuse = 45 * time.Second
)

type serviceTokens struct {
	secret string
	kid    string

	mu       sync.Mutex
	proxy    string
	proxyExp time.Time
}

func (s *serviceTokens) sign(subject string, extra map[string]any) (string, error) {
	claims := map[string]any{
		"iss": serviceTokenIssuer,
		"aud": serviceTokenAudience,
		"sub": subject,
	}
	for k, v := range extra {
		claims[k] = v
	}
	return signHS256(claims, s.secret, serviceTokenTTL, s.kid)
}

// proxyAuthorization lets the auth API trust the client address and user agent
// this adapter forwards.
func (s *serviceTokens) proxyAuthorization() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.proxy != "" && time.Now().Before(s.proxyExp) {
		return s.proxy
	}
	token, err := s.sign(proxyTokenSubject, nil)
	if err != nil {
		return ""
	}
	s.proxy = "Bearer " + token
	s.proxyExp = time.Now().Add(proxyTokenReuse)
	return s.proxy
}

// deliveryAuthorization asks the auth API to return a message instead of sending
// it.
func (s *serviceTokens) deliveryAuthorization() string {
	token, err := s.sign(deliveryTokenSubject, nil)
	if err != nil {
		return ""
	}
	return "Bearer " + token
}
