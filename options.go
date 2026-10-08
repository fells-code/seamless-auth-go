package seamlessauth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	// It is the API's API_SERVICE_TOKEN. At least 32 characters.
	ServiceSecret string
	// JWKSKid is the kid header on service tokens.
	JWKSKid string

	CookieDomain string
	// InsecureCookies drops the Secure attribute, for local development over HTTP.
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

	// ResolveClientIP returns the end user's address. Defaults to the connecting
	// peer. Behind a proxy, use TrustedProxies.
	ResolveClientIP func(r *http.Request) string

	// DisableManifestFetch uses only the manifest bundled with this version
	// instead of fetching the auth API's on the first request.
	DisableManifestFetch bool

	HTTPClient *http.Client
	Logf       func(format string, args ...any)
}

const minSecretLength = 32

func (o Options) withDefaults() (Options, error) {
	o.AuthServerURL = strings.TrimRight(o.AuthServerURL, "/")
	if o.AuthServerURL == "" {
		return o, errors.New("seamlessauth: AuthServerURL is required")
	}
	if len(o.CookieSecret) < minSecretLength {
		return o, fmt.Errorf("seamlessauth: CookieSecret must be at least %d characters", minSecretLength)
	}
	if len(o.ServiceSecret) < minSecretLength {
		return o, fmt.Errorf("seamlessauth: ServiceSecret must be at least %d characters", minSecretLength)
	}

	if o.AuthServerIssuer == "" {
		o.AuthServerIssuer = o.AuthServerURL
	}
	if o.Audience == "" {
		o.Audience = o.AuthServerIssuer
	}
	if o.Logf == nil {
		o.Logf = log.Printf
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
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
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
