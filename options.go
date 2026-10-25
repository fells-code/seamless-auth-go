package seamlessauth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Options configures an Adapter.
type Options struct {
	// AuthServerURL is where the adapter reaches the auth API, without a trailing
	// slash.
	AuthServerURL string
	// AuthServerIssuer is the expected iss of the auth API's tokens. Defaults to
	// AuthServerURL. Set it when this server reaches the API at another URL than
	// the issuer it advertises.
	AuthServerIssuer string
	// Audience is the expected aud of the auth API's tokens. The auth API sets it
	// to its issuer, so it defaults to AuthServerIssuer.
	Audience string

	// CookieSecret signs the session cookies. At least 32 characters.
	CookieSecret string
	// ServiceSecret signs the service tokens the auth API trusts this adapter by.
	// It holds the same value as the API's API_SERVICE_TOKEN; apps conventionally
	// read it from SEAMLESS_SERVICE_TOKEN. At least 32 characters.
	ServiceSecret string
	// JWKSKid is the kid header on service tokens.
	JWKSKid string

	CookieDomain string
	// InsecureCookies drops the Secure attribute, for local development over HTTP.
	// It also lets the placeholder secrets from the examples through.
	InsecureCookies bool
	// CookieSameSite defaults to None for secure cookies and Lax otherwise.
	CookieSameSite http.SameSite
	// AllowedOrigins, when set, is the only cross-origin callers allowed to make
	// state-changing requests while cookies are SameSite=None.
	AllowedOrigins []string

	AccessCookieName       string
	RegistrationCookieName string
	RefreshCookieName      string
	PreAuthCookieName      string

	// Deliver sends OTP codes and magic links through the application's own
	// transports. When set, the adapter asks the auth API for the message instead
	// of having the API send it.
	Deliver func(ctx context.Context, delivery Delivery) error
	// DeliverAccountNotices says Deliver also sends account_notice_email and
	// account_notice_sms. Only then does the adapter ask the auth API to hand it
	// the notices that tell an owner their account is being recovered; otherwise
	// the API sends them itself. The API counts a notice it hands back as the
	// owner being told, so set it only when Deliver really sends both kinds.
	DeliverAccountNotices bool

	// AllowRecoverySessions lets RequireAuth and Authenticate admit an access
	// token carrying recovery: true, which a recovery code issues before the user
	// has enrolled a new passkey or authenticator app. By default such a session
	// is refused with 403 enrollment_required.
	AllowRecoverySessions bool

	// ResolveClientIP returns the end user's address. Defaults to the connecting
	// peer. Behind a proxy, use TrustedProxies.
	ResolveClientIP func(r *http.Request) string

	// DisableManifestFetch uses only the manifest bundled with this version
	// instead of fetching the auth API's on the first request.
	DisableManifestFetch bool

	// HTTPClient makes the calls to the auth API. It never follows a redirect: a
	// supplied client is copied with a CheckRedirect that refuses them, and one
	// with no Timeout gets the default.
	HTTPClient *http.Client
	Logf       func(format string, args ...any)
}

const (
	minSecretLength = 32
	upstreamTimeout = 15 * time.Second
)

// isPlaceholderSecret is a value from the examples and starters, which length
// alone does not catch.
func isPlaceholderSecret(secret string) bool {
	return strings.EqualFold(secret, "dev-only-cookie-signing-key-replace-me") ||
		strings.EqualFold(secret, "GRAB_FROM_SEAMLESS_AUTH_PORTAL_DEV") ||
		strings.Contains(strings.ToLower(secret), "replace-me")
}

func noRedirects(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func (o Options) withDefaults() (Options, error) {
	o.AuthServerURL = strings.TrimRight(strings.TrimSpace(o.AuthServerURL), "/")
	if o.AuthServerURL == "" {
		return o, errors.New("seamlessauth: AuthServerURL is required")
	}
	if u, err := url.Parse(o.AuthServerURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return o, errors.New("seamlessauth: AuthServerURL must be an http or https URL")
	}
	if len(o.CookieSecret) < minSecretLength {
		return o, fmt.Errorf("seamlessauth: CookieSecret must be at least %d characters", minSecretLength)
	}
	if len(o.ServiceSecret) < minSecretLength {
		return o, fmt.Errorf("seamlessauth: ServiceSecret must be at least %d characters", minSecretLength)
	}
	if o.Logf == nil {
		o.Logf = log.Printf
	}
	for _, secret := range []struct{ name, value string }{
		{"CookieSecret", o.CookieSecret},
		{"ServiceSecret", o.ServiceSecret},
	} {
		if !isPlaceholderSecret(secret.value) {
			continue
		}
		name := secret.name
		if !o.InsecureCookies {
			return o, fmt.Errorf("seamlessauth: %s is a placeholder value; set a real secret", name)
		}
		o.Logf("[seamless-auth] %s is a placeholder value, allowed only because InsecureCookies is set.", name)
	}

	if o.AuthServerIssuer == "" {
		o.AuthServerIssuer = o.AuthServerURL
	}
	if o.Audience == "" {
		o.Audience = o.AuthServerIssuer
	}
	if o.JWKSKid == "" {
		o.JWKSKid = "dev-main"
		o.Logf("[seamless-auth] JWKSKid is not set and defaults to %q, a placeholder. Set it to name the service-token key explicitly.", o.JWKSKid)
	}
	if o.CookieSameSite == 0 || o.CookieSameSite == http.SameSiteDefaultMode {
		if o.InsecureCookies {
			o.CookieSameSite = http.SameSiteLaxMode
		} else {
			o.CookieSameSite = http.SameSiteNoneMode
		}
	}
	if o.AccessCookieName == "" {
		o.AccessCookieName = "seamless-access"
	}
	if o.RegistrationCookieName == "" {
		o.RegistrationCookieName = "seamless-ephemeral"
	}
	if o.RefreshCookieName == "" {
		o.RefreshCookieName = "seamless-refresh"
	}
	// Shares the registration cookie on purpose: registration and sign-in never
	// hold an ephemeral cookie at the same time.
	if o.PreAuthCookieName == "" {
		o.PreAuthCookieName = "seamless-ephemeral"
	}
	// A client that follows redirects would carry the service token and the
	// user's bearer token to wherever the auth API pointed it.
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: upstreamTimeout}
	} else {
		client := *o.HTTPClient
		o.HTTPClient = &client
	}
	o.HTTPClient.CheckRedirect = noRedirects
	// A call that never returns would hold a refresh flight, and every tab
	// waiting on it.
	if o.HTTPClient.Timeout == 0 {
		o.HTTPClient.Timeout = upstreamTimeout
	}
	return o, nil
}

func (o Options) cookieName(held string) string {
	switch held {
	case "access":
		return o.AccessCookieName
	case "registration":
		return o.RegistrationCookieName
	case "refresh":
		return o.RefreshCookieName
	default:
		return o.PreAuthCookieName
	}
}
