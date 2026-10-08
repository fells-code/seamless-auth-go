package seamlessauth

import (
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

var b64 = base64.RawURLEncoding

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

// signHS256 issues a compact HS256 JWT. claims gains iat and, when ttl is
// positive, exp.
func signHS256(claims map[string]any, secret string, ttl time.Duration, kid string) (string, error) {
	now := time.Now()
	body := make(map[string]any, len(claims)+2)
	for k, v := range claims {
		body[k] = v
	}
	body["iat"] = now.Unix()
	if ttl > 0 {
		body["exp"] = now.Add(ttl).Unix()
	}

	header, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return "", err
	}

	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))

	return signingInput + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

type parsedJWT struct {
	header       jwtHeader
	claims       map[string]any
	signingInput string
	signature    []byte
}

func parseJWT(token string) (*parsedJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}

	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	rawClaims, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}

	var parsed parsedJWT
	if err := json.Unmarshal(rawHeader, &parsed.header); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(rawClaims)))
	decoder.UseNumber()
	if err := decoder.Decode(&parsed.claims); err != nil {
		return nil, err
	}
	parsed.signingInput = parts[0] + "." + parts[1]
	parsed.signature = signature

	return &parsed, nil
}

// verifyHS256 returns the claims of a token this adapter signed, or an error when
// the signature, algorithm or expiry does not hold.
func verifyHS256(token, secret string) (map[string]any, error) {
	parsed, err := parseJWT(token)
	if err != nil {
		return nil, err
	}
	if parsed.header.Alg != "HS256" {
		return nil, errors.New("unexpected algorithm")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parsed.signingInput))
	if subtle.ConstantTimeCompare(mac.Sum(nil), parsed.signature) != 1 {
		return nil, errors.New("bad signature")
	}
	if err := checkTimes(parsed.claims, time.Now()); err != nil {
		return nil, err
	}

	return parsed.claims, nil
}

func verifyRS256(parsed *parsedJWT, key *rsa.PublicKey) error {
	if parsed.header.Alg != "RS256" {
		return errors.New("unexpected algorithm")
	}
	digest := sha256.Sum256([]byte(parsed.signingInput))
	return rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], parsed.signature)
}

const clockSkew = 5 * time.Second

func checkTimes(claims map[string]any, now time.Time) error {
	if exp, ok := numericClaim(claims, "exp"); ok && now.After(time.Unix(exp, 0).Add(clockSkew)) {
		return errors.New("token expired")
	}
	if nbf, ok := numericClaim(claims, "nbf"); ok && now.Add(clockSkew).Before(time.Unix(nbf, 0)) {
		return errors.New("token not yet valid")
	}
	return nil
}

func numericClaim(claims map[string]any, name string) (int64, bool) {
	switch v := claims[name].(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			f, ferr := v.Float64()
			return int64(f), ferr == nil
		}
		return n, true
	case float64:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

func stringClaim(claims map[string]any, name string) string {
	s, _ := claims[name].(string)
	return s
}

// audienceMatches accepts aud as a string or an array, as RFC 7519 allows.
func audienceMatches(claims map[string]any, audience string) bool {
	switch aud := claims["aud"].(type) {
	case string:
		return aud == audience
	case []any:
		for _, a := range aud {
			if s, ok := a.(string); ok && s == audience {
				return true
			}
		}
	}
	return false
}
