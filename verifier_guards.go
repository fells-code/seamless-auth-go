package seamlessauth

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RequireScope answers 403 insufficient_scope unless the token carries every one
// of scopes. Put it inside RequireToken. It panics when given no scope, or a
// scope that is empty or holds a space, a quote or a backslash.
func (v *Verifier) RequireScope(scopes ...string) func(http.Handler) http.Handler {
	if len(scopes) == 0 {
		panic("seamlessauth: RequireScope needs at least one scope")
	}
	for _, s := range scopes {
		if !isChallengeToken(s) {
			panic(fmt.Sprintf("seamlessauth: %q is not a valid scope", s))
		}
	}
	required := strings.Join(scopes, " ")
	challenge := `Bearer error="insufficient_scope", scope="` + required + `"`
	body := struct {
		Error string `json:"error"`
		Scope string `json:"scope"`
	}{"insufficient_scope", required}

	return guard(func(w http.ResponseWriter, _ *http.Request, user *TokenUser) bool {
		for _, s := range scopes {
			if !contains(user.Scopes, s) {
				writeBearerError(w, http.StatusForbidden, challenge, body)
				return false
			}
		}
		return true
	})
}

// RequireRole answers 403 insufficient_role unless the token's roles grant at
// least one of roles, matched as RoleGrantsAccess does. Put it inside
// RequireToken. It panics when given no role.
func (v *Verifier) RequireRole(roles ...string) func(http.Handler) http.Handler {
	if len(roles) == 0 {
		panic("seamlessauth: RequireRole needs at least one role")
	}
	return guard(func(w http.ResponseWriter, _ *http.Request, user *TokenUser) bool {
		for _, required := range roles {
			for _, granted := range user.Roles {
				if RoleGrantsAccess(granted, required) {
					return true
				}
			}
		}
		writeBearerError(w, http.StatusForbidden, "", map[string]string{"error": "insufficient_role"})
		return false
	})
}

// StepUp is what RequireStepUp asks of the user's authentication (RFC 9470).
type StepUp struct {
	// ACRValues accepts a token whose acr is one of them. Listing "phr" also
	// accepts "phrh", which is stronger.
	ACRValues []string
	// AMR requires every one of these methods in the token's amr.
	AMR []string
	// MaxAge requires the user to have authenticated within it, by auth_time. A
	// whole number of seconds; zero means just now.
	MaxAge *time.Duration
}

// RequireStepUp answers 401 insufficient_user_authentication, with the RFC 9470
// challenge, unless the token meets step. Put it inside RequireToken. It is an
// error to ask for nothing, or for a negative or fractional MaxAge.
func (v *Verifier) RequireStepUp(step StepUp) (func(http.Handler) http.Handler, error) {
	if len(step.ACRValues) == 0 && len(step.AMR) == 0 && step.MaxAge == nil {
		return nil, errors.New("seamlessauth: RequireStepUp needs ACRValues, AMR or MaxAge")
	}
	for _, values := range [][]string{step.ACRValues, step.AMR} {
		for _, value := range values {
			if !isChallengeToken(value) {
				return nil, fmt.Errorf("seamlessauth: %q is not a valid acr or amr value", value)
			}
		}
	}
	var maxAge *int64
	if step.MaxAge != nil {
		if *step.MaxAge < 0 || *step.MaxAge%time.Second != 0 {
			return nil, errors.New("seamlessauth: MaxAge must be a whole, non-negative number of seconds")
		}
		seconds := int64(*step.MaxAge / time.Second)
		maxAge = &seconds
	}

	accepted := append([]string(nil), step.ACRValues...)
	if contains(step.ACRValues, "phr") {
		accepted = append(accepted, "phrh")
	}
	type challengeBody struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
		ACRValues        string `json:"acr_values,omitempty"`
		MaxAge           *int64 `json:"max_age,omitempty"`
	}
	challenge := func(description string) (string, challengeBody) {
		header := `Bearer error="insufficient_user_authentication", error_description="` + description + `"`
		body := challengeBody{Error: "insufficient_user_authentication", ErrorDescription: description, MaxAge: maxAge}
		if len(step.ACRValues) > 0 {
			body.ACRValues = strings.Join(step.ACRValues, " ")
			header += `, acr_values="` + body.ACRValues + `"`
		}
		if maxAge != nil {
			header += `, max_age="` + strconv.FormatInt(*maxAge, 10) + `"`
		}
		return header, body
	}

	return guard(func(w http.ResponseWriter, _ *http.Request, user *TokenUser) bool {
		levelMet := len(step.ACRValues) == 0 || (user.ACR != "" && contains(accepted, user.ACR))
		for _, method := range step.AMR {
			if !contains(user.AMR, method) {
				levelMet = false
			}
		}
		recent := maxAge == nil ||
			(user.hasAuthTime && unixSeconds(v.now())-user.authTime <= float64(*maxAge))
		if levelMet && recent {
			return true
		}
		description := "More recent authentication is required"
		if !levelMet {
			description = "A different authentication level is required"
		}
		header, body := challenge(description)
		writeBearerError(w, http.StatusUnauthorized, header, body)
		return false
	}), nil
}

// guard runs check on the verified user, answering as a missing token when
// RequireToken did not run first.
func guard(check func(http.ResponseWriter, *http.Request, *TokenUser) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user, ok := TokenUserFromContext(r.Context())
			if !ok || user == nil {
				writeMissingToken(w)
				return
			}
			if check(w, r, user) {
				next.ServeHTTP(w, r)
			}
		})
	}
}

// isChallengeToken is a value that can be quoted in a WWW-Authenticate challenge
// and joined with spaces without changing meaning.
func isChallengeToken(s string) bool {
	return s != "" && !strings.ContainsAny(s, " \t\r\n\"\\")
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// RoleGrantsAccess reports whether a granted role satisfies a required one, as
// roleGrantsAccess in @seamless-auth/types does: a ":*" suffix grants every role
// under its prefix, an unscoped role grants every role beneath it, and a ":write"
// role implies the matching ":read" role.
func RoleGrantsAccess(granted, required string) bool {
	granted = trimJS(granted)
	required = trimJS(required)
	if granted == "" || required == "" {
		return false
	}
	if granted == required {
		return true
	}
	if strings.HasSuffix(granted, ":*") {
		prefix := granted[:len(granted)-2]
		return required == prefix || strings.HasPrefix(required, prefix+":")
	}
	if !strings.Contains(required, ":") {
		return false
	}
	if !strings.Contains(granted, ":") {
		return strings.HasPrefix(required, granted+":")
	}
	grantedParts := strings.Split(granted, ":")
	requiredParts := strings.Split(required, ":")
	grantedPrefix, grantedAction := grantedParts[:len(grantedParts)-1], grantedParts[len(grantedParts)-1]
	requiredPrefix, requiredAction := requiredParts[:len(requiredParts)-1], requiredParts[len(requiredParts)-1]
	if grantedAction != "write" || requiredAction != "read" || len(grantedPrefix) != len(requiredPrefix) {
		return false
	}
	for i := range grantedPrefix {
		if grantedPrefix[i] != requiredPrefix[i] {
			return false
		}
	}
	return true
}

// trimJS trims what String.prototype.trim does, which differs from
// strings.TrimSpace at U+0085 and U+FEFF.
func trimJS(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', ' ', 0x00A0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
			return true
		}
		return r >= 0x2000 && r <= 0x200A
	})
}
