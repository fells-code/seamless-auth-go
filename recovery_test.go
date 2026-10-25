package seamlessauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func recoveryToken(t *testing.T, api *fakeAPI, sub string) string {
	return signRS256(t, map[string]any{
		"sub": sub, "sid": "s-1", "typ": "access", "recovery": true, "iss": api.server.URL, "aud": api.server.URL,
	})
}

func TestRequireAuthRefusesARecoverySession(t *testing.T) {
	api := newFakeAPI(t)
	token := recoveryToken(t, api, "u1")
	byCookie := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": token}))
	byBearer := withHeader("Authorization", "Bearer "+token)

	refusing := newTestAdapter(t, api)
	for name, setup := range map[string]func(*http.Request){"cookie": byCookie, "bearer": byBearer} {
		t.Run(name, func(t *testing.T) {
			rec := call(guarded(refusing), setup)
			if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"error":"enrollment_required"`) {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			req, _ := http.NewRequest("GET", "/api/me", nil)
			setup(req)
			if _, err := refusing.Authenticate(req); !errors.Is(err, ErrEnrollmentRequired) {
				t.Fatalf("Authenticate err %v", err)
			}
		})
	}

	allowing := newTestAdapter(t, api, func(o *Options) { o.AllowRecoverySessions = true })
	for name, setup := range map[string]func(*http.Request){"cookie": byCookie, "bearer": byBearer} {
		t.Run(name+" allowed", func(t *testing.T) {
			if rec := call(guarded(allowing), setup); rec.Code != http.StatusOK {
				t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
			}
			req, _ := http.NewRequest("GET", "/api/me", nil)
			setup(req)
			if user, err := allowing.Authenticate(req); err != nil || !user.Recovery {
				t.Fatalf("user %+v err %v", user, err)
			}
		})
	}

	ordinary := apiToken(t, api, "u1", "access")
	req, _ := http.NewRequest("GET", "/api/me", nil)
	req.Header.Set("Authorization", "Bearer "+ordinary)
	if user, err := refusing.Authenticate(req); err != nil || user.Recovery {
		t.Fatalf("user %+v err %v", user, err)
	}
}

// refreshingAPI answers /refresh with an ordinary session and a new refresh token
// each time.
func refreshingAPI(t *testing.T, api *fakeAPI) *atomic.Int32 {
	var n atomic.Int32
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		s := session(t, api, "u1")
		s["refreshToken"] = fmt.Sprintf("refresh-%d", n.Add(1))
		writeJSON(w, 200, s)
	})
	return &n
}

func TestEnrollingFromARecoverySessionRefreshesItsCookie(t *testing.T) {
	for _, path := range []string{"/webauthn/register/finish", "/totp/enroll/verify"} {
		t.Run(path, func(t *testing.T) {
			api := newFakeAPI(t)
			api.on("POST", path, respond(200, map[string]any{"message": "Success"}))
			refreshes := refreshingAPI(t, api)
			a := newTestAdapter(t, api)

			r := do(t, a, "POST", path, `{}`,
				withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": recoveryToken(t, api, "u1")})),
				withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "refresh-0"})))

			if r.status != 200 || r.body["message"] != "Success" {
				t.Fatalf("status %d body %v", r.status, r.body)
			}
			if refreshes.Load() != 1 {
				t.Fatalf("%d refreshes", refreshes.Load())
			}
			if got := api.callsTo("POST", "/refresh")[0].header.Get("Authorization"); got != "Bearer refresh-0" {
				t.Fatalf("refreshed with %q", got)
			}
			req, _ := http.NewRequest("GET", "/api/me", nil)
			req.AddCookie(r.cookies["seamless-access"])
			if user, err := a.Authenticate(req); err != nil || user.Recovery {
				t.Fatalf("the new cookie still holds a recovery session: %+v %v", user, err)
			}
			if r.cookies["seamless-refresh"] == nil {
				t.Fatal("the rotated refresh token was not stored")
			}
		})
	}
}

func TestEnrollingAfterASilentRefreshRotatesTheNewRefreshToken(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/totp/enroll/verify", respond(200, map[string]any{"message": "Success"}))
	var n atomic.Int32
	api.on("POST", "/refresh", func(w http.ResponseWriter, _ *http.Request) {
		s := session(t, api, "u1")
		if n.Add(1) == 1 {
			s["token"] = recoveryToken(t, api, "u1")
		}
		s["refreshToken"] = fmt.Sprintf("refresh-%d", n.Load())
		writeJSON(w, 200, s)
	})
	a := newTestAdapter(t, api)

	r := do(t, a, "POST", "/totp/enroll/verify", `{}`,
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "refresh-0"})))

	if r.status != 200 {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	calls := api.callsTo("POST", "/refresh")
	if len(calls) != 2 || calls[1].header.Get("Authorization") != "Bearer refresh-1" {
		t.Fatalf("refresh calls %+v", calls)
	}
	req, _ := http.NewRequest("GET", "/api/me", nil)
	req.AddCookie(r.cookies["seamless-access"])
	if user, err := a.Authenticate(req); err != nil || user.Recovery {
		t.Fatalf("the new cookie still holds a recovery session: %+v %v", user, err)
	}
}

func TestEnrollingWithoutARecoverySessionDoesNotRefresh(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/webauthn/register/finish", respond(200, map[string]any{"message": "Success"}))
	refreshes := refreshingAPI(t, api)
	a := newTestAdapter(t, api)

	do(t, a, "POST", "/webauthn/register/finish", `{}`,
		withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": apiToken(t, api, "u1", "access")})),
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "refresh-0"})))
	// A bearer client holds its own refresh token and refreshes for itself.
	do(t, a, "POST", "/webauthn/register/finish", `{}`,
		withHeader(transportHeader, "bearer"), withHeader("Authorization", "Bearer "+recoveryToken(t, api, "u1")))

	if refreshes.Load() != 0 {
		t.Fatalf("%d refreshes", refreshes.Load())
	}
}

func TestAFailedRefreshAfterEnrollmentKeepsTheEnrollment(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/webauthn/register/finish", respond(200, map[string]any{"message": "Success"}))
	api.on("POST", "/refresh", respond(401, map[string]any{"error": "invalid_refresh_token"}))

	r := do(t, newTestAdapter(t, api), "POST", "/webauthn/register/finish", `{}`,
		withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": recoveryToken(t, api, "u1")})),
		withCookie(signedCookie(t, "seamless-refresh", map[string]any{"sub": "u1", "refreshToken": "refresh-0"})))

	if r.status != 200 || r.body["message"] != "Success" || len(r.cookies) != 0 {
		t.Fatalf("status %d body %v cookies %v", r.status, r.body, r.cookies)
	}
}

func recoveryVerifyResponse() map[string]any {
	return map[string]any{
		"state": "pending", "requestedAt": "2026-10-24T00:00:00Z", "completesAt": "2026-10-25T00:00:00Z",
		"deliveries": []any{
			map[string]any{
				"kind": "account_notice_email", "to": "owner@b.test", "notice": "account_recovery_opened",
				"subject": "Recovery requested", "text": "Someone asked to recover your account.",
				"cancelUrl": "https://app.test/recovery/cancel#secret-cancel",
			},
			map[string]any{
				"kind": "account_notice_sms", "to": "+15550100", "notice": "account_recovery_opened",
				"text": "Recovery requested.", "cancelUrl": "https://app.test/recovery/cancel#secret-cancel-2",
			},
		},
	}
}

func preAuthCookie(t *testing.T) func(*http.Request) {
	return withCookie(signedCookie(t, "seamless-ephemeral", map[string]any{"sub": "u1", "token": "pre-auth"}))
}

func TestRecoveryNoticesAreDeliveredByTheApplication(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/verify", respond(200, recoveryVerifyResponse()))
	var mu sync.Mutex
	var got []Delivery
	var logs []string
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(_ context.Context, d Delivery) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, d)
			return nil
		}
		o.DeliverAccountNotices = true
		o.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	})

	for _, bearer := range []bool{false, true} {
		got = nil
		setup := preAuthCookie(t)
		if bearer {
			setup = func(r *http.Request) {
				r.Header.Set(transportHeader, "bearer")
				r.Header.Set("Authorization", "Bearer pre-auth")
			}
		}
		r := do(t, a, "POST", "/recovery/verify", `{"code":"123456"}`, setup)

		if r.status != 200 || r.body["state"] != "pending" {
			t.Fatalf("status %d body %v", r.status, r.body)
		}
		if _, ok := r.body["deliveries"]; ok {
			t.Fatal("the notices reached the client")
		}
		if len(got) != 2 {
			t.Fatalf("deliveries %v", got)
		}
		email, sms := got[0], got[1]
		if email.Kind != DeliveryAccountNoticeEmail || email.To != "owner@b.test" || email.Subject != "Recovery requested" ||
			email.Text == "" || email.Notice != "account_recovery_opened" || email.CancelURL != "https://app.test/recovery/cancel#secret-cancel" {
			t.Fatalf("email notice %#v", email)
		}
		if sms.Kind != DeliveryAccountNoticeSMS || sms.To != "+15550100" || sms.Text != "Recovery requested." ||
			sms.CancelURL != "https://app.test/recovery/cancel#secret-cancel-2" {
			t.Fatalf("sms notice %#v", sms)
		}
	}

	call := api.callsTo("POST", "/recovery/verify")[0]
	if call.header.Get(deliveryModeHeader) != "external" ||
		call.header.Get(deliveryKindsHeader) != "account_notice_email,account_notice_sms" {
		t.Fatalf("headers %v", call.header)
	}
	if call.header.Get("Authorization") != "Bearer pre-auth" {
		t.Fatalf("authorization %q", call.header.Get("Authorization"))
	}
	service, _ := verifyHS256(strings.TrimPrefix(call.header.Get("X-Seamless-Service-Token"), "Bearer "), testService)
	if service["sub"] != deliveryTokenSubject {
		t.Fatalf("delivery service token %v", service)
	}
	for _, line := range logs {
		if strings.Contains(line, "secret-cancel") {
			t.Fatalf("logged a cancel link: %s", line)
		}
	}
	if s := fmt.Sprintf("%v %+v %#v %s", got[0], got[0], got[0], got[0]); strings.Contains(s, "secret-cancel") {
		t.Fatalf("a printed Delivery carries its cancel link: %s", s)
	}
}

func TestRecoveryNoticesStayWithTheAPIUnlessTheApplicationSendsThem(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/verify", respond(200, recoveryVerifyResponse()))
	var delivered int
	deliver := func(context.Context, Delivery) error { delivered++; return nil }

	for name, a := range map[string]*Adapter{
		"no Deliver":                   newTestAdapter(t, api),
		"Deliver without notice kinds": newTestAdapter(t, api, func(o *Options) { o.Deliver = deliver }),
		"notice kinds without Deliver": newTestAdapter(t, api, func(o *Options) { o.DeliverAccountNotices = true }),
	} {
		t.Run(name, func(t *testing.T) {
			r := do(t, a, "POST", "/recovery/verify", `{"code":"123456"}`, preAuthCookie(t))
			if r.status != 200 {
				t.Fatalf("status %d", r.status)
			}
			if _, ok := r.body["deliveries"]; ok {
				t.Fatal("the notices reached the client")
			}
			calls := api.callsTo("POST", "/recovery/verify")
			last := calls[len(calls)-1]
			if last.header.Get(deliveryModeHeader) != "" || last.header.Get(deliveryKindsHeader) != "" {
				t.Fatalf("claimed to deliver notices: %v", last.header)
			}
		})
	}
	if delivered != 0 {
		t.Fatalf("delivered %d notices nobody asked for", delivered)
	}
}

func TestOneDeliveredNoticeIsEnough(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/verify", respond(200, recoveryVerifyResponse()))
	api.on("POST", "/recovery/cancel", respond(200, map[string]any{"state": "cancelled"}))
	var attempts []string
	a := newTestAdapter(t, api, func(o *Options) {
		o.DeliverAccountNotices = true
		o.Deliver = func(_ context.Context, d Delivery) error {
			attempts = append(attempts, d.Kind)
			if d.Kind == DeliveryAccountNoticeEmail {
				return errors.New("smtp down")
			}
			return nil
		}
	})

	r := do(t, a, "POST", "/recovery/verify", `{"code":"123456"}`, preAuthCookie(t))

	if r.status != 200 || r.body["state"] != "pending" || r.body["deliveries"] != nil {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if len(attempts) != 2 {
		t.Fatalf("attempts %v", attempts)
	}
	if len(api.callsTo("POST", "/recovery/cancel")) != 0 {
		t.Fatal("cancelled a request whose owner was told")
	}
}

func TestARecoveryNoNoticeReachedIsCancelled(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/verify", respond(200, recoveryVerifyResponse()))
	api.on("POST", "/recovery/cancel", respond(200, map[string]any{"state": "cancelled"}))
	var attempts int
	var logs []string
	a := newTestAdapter(t, api, func(o *Options) {
		o.DeliverAccountNotices = true
		o.Deliver = func(context.Context, Delivery) error {
			attempts++
			return errors.New("transport down")
		}
		o.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	})

	r := do(t, a, "POST", "/recovery/verify", `{"code":"123456"}`, preAuthCookie(t))

	if r.status != http.StatusServiceUnavailable || r.body["error"] != "recovery_notice_failed" || len(r.body) != 1 {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if attempts != 2 {
		t.Fatalf("%d attempts", attempts)
	}
	calls := api.callsTo("POST", "/recovery/cancel")
	if len(calls) != 1 {
		t.Fatalf("%d cancel calls", len(calls))
	}
	cancel := calls[0]
	if cancel.body != `{"cancelToken":"secret-cancel"}` || cancel.header.Get("Content-Type") != "application/json" {
		t.Fatalf("cancel body %q", cancel.body)
	}
	if cancel.header.Get("Authorization") != "" {
		t.Fatalf("cancel sent a credential: %q", cancel.header.Get("Authorization"))
	}
	service, _ := verifyHS256(strings.TrimPrefix(cancel.header.Get("X-Seamless-Service-Token"), "Bearer "), testService)
	if service["sub"] != proxyTokenSubject {
		t.Fatalf("cancel service token %v", service)
	}
	for _, line := range logs {
		if strings.Contains(line, "secret-cancel") {
			t.Fatalf("logged a cancel token: %s", line)
		}
	}
}

func TestAnUnknownDeliveryKindIsSkipped(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/otp/generate-login-email-otp", respond(200, map[string]any{
		"message":  "success",
		"delivery": map[string]any{"kind": "carrier_pigeon", "to": "a@b.test", "token": "123456"},
	}))
	var delivered int
	var logs []string
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(context.Context, Delivery) error { delivered++; return nil }
		o.Logf = func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }
	})

	r := do(t, a, "POST", "/otp/generate-login-email-otp", "", preAuthCookie(t))

	if r.status != 200 || r.body["delivery"] != nil {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if delivered != 0 {
		t.Fatal("handed an unknown kind to Deliver")
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "carrier_pigeon") || strings.Contains(logs[0], "123456") {
		t.Fatalf("logs %v", logs)
	}
}

func TestARecoveryCodeCarriesItsPurpose(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/start", respond(200, map[string]any{
		"message":  "sent",
		"delivery": map[string]any{"kind": "otp_sms", "to": "+15550100", "token": 123456, "purpose": "account_recovery"},
	}))
	var got Delivery
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(_ context.Context, d Delivery) error { got = d; return nil }
	})

	r := do(t, a, "POST", "/recovery/start", `{"identifier":"+15550100"}`, preAuthCookie(t))

	if r.status != 200 || r.body["delivery"] != nil {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if got.Kind != DeliveryOTPSMS || got.Token != "123456" || got.Purpose != PurposeAccountRecovery {
		t.Fatalf("delivery %+v", got)
	}
	if s := fmt.Sprint(got); strings.Contains(s, "123456") {
		t.Fatalf("a printed Delivery carries its code: %s", s)
	}
}

func TestRecoveryAndPolicyRoutesPassThrough(t *testing.T) {
	api := newFakeAPI(t)
	access := withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "access-token"}))
	cases := []struct {
		method, path  string
		setup         func(*http.Request)
		authorization string
	}{
		{"POST", "/recovery/start", preAuthCookie(t), "Bearer pre-auth"},
		{"GET", "/recovery/status", preAuthCookie(t), "Bearer pre-auth"},
		{"POST", "/recovery/cancel", func(*http.Request) {}, ""},
		{"GET", "/recovery/requests", access, "Bearer access-token"},
		{"DELETE", "/recovery/requests/req-1", access, "Bearer access-token"},
		{"GET", "/recovery-codes", access, "Bearer access-token"},
		{"POST", "/recovery-codes", access, "Bearer access-token"},
		{"GET", "/system-config/policy", access, "Bearer access-token"},
		{"PUT", "/system-config/policy/draft", access, "Bearer access-token"},
		{"DELETE", "/system-config/policy/draft", access, "Bearer access-token"},
		{"POST", "/system-config/policy/publish", access, "Bearer access-token"},
		{"POST", "/system-config/policy/rollback", access, "Bearer access-token"},
		{"GET", "/system-config/policy/versions", access, "Bearer access-token"},
		{"POST", "/system-config/policy/dry-run", access, "Bearer access-token"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			api.on(c.method, c.path, respond(200, map[string]any{"ok": true}))
			body := ""
			if c.method != "GET" && c.method != "DELETE" {
				body = `{}`
			}
			r := do(t, newTestAdapter(t, api), c.method, c.path, body, c.setup)
			if r.status != 200 || r.body["ok"] != true {
				t.Fatalf("status %d body %v", r.status, r.body)
			}
			calls := api.callsTo(c.method, c.path)
			if got := calls[len(calls)-1].header.Get("Authorization"); got != c.authorization {
				t.Fatalf("authorization %q", got)
			}
		})
	}
}

func TestRecoveryAndStepUpRefusalsPassThrough(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/recovery/verify", respond(503, map[string]any{"error": "recovery_notice_failed"}))
	api.on("POST", "/admin/organizations", respond(403, map[string]any{
		"error": "step_up_required", "message": "Recent step-up authentication is required",
		"fresh": false, "maxAgeSeconds": 300,
	}))
	a := newTestAdapter(t, api)

	r := do(t, a, "POST", "/recovery/verify", `{"code":"123456"}`, preAuthCookie(t))
	if r.status != http.StatusServiceUnavailable || r.body["error"] != "recovery_notice_failed" {
		t.Fatalf("status %d body %v", r.status, r.body)
	}

	r = do(t, a, "POST", "/admin/organizations", `{"name":"x"}`,
		withCookie(signedCookie(t, "seamless-access", map[string]any{"sub": "u1", "token": "access-token"})))
	if r.status != http.StatusForbidden || r.body["error"] != "step_up_required" || r.body["fresh"] != false ||
		r.body["maxAgeSeconds"] != float64(300) {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
}

func TestTheManifestMarksRoutesThatCarryNotices(t *testing.T) {
	m := BundledManifest()
	match, ok := m.match("POST", "/recovery/verify")
	if !ok || !match.route.Notices || match.route.Credential != "preAuth" {
		t.Fatalf("route %+v", match.route)
	}

	parsed, err := ParseManifest([]byte(`{"schemaVersion":1,"apiVersion":"0.20.0","routes":[
		{"method":"POST","path":"/recovery/verify","credential":"preAuth","notices":true}]}`))
	if err != nil || !parsed.Routes[0].Notices {
		t.Fatalf("manifest %+v %v", parsed, err)
	}
}

func TestANoticeIsNotHandedToADeliverThatDoesNotSendNotices(t *testing.T) {
	api := newFakeAPI(t)
	api.on("POST", "/otp/generate-login-email-otp", respond(200, map[string]any{
		"message":  "success",
		"delivery": map[string]any{"kind": "account_notice_email", "to": "a@b.test", "subject": "s", "text": "t", "notice": "identity_changed"},
	}))
	var delivered int
	a := newTestAdapter(t, api, func(o *Options) {
		o.Deliver = func(context.Context, Delivery) error { delivered++; return nil }
	})

	if r := do(t, a, "POST", "/otp/generate-login-email-otp", "", preAuthCookie(t)); r.status != 200 {
		t.Fatalf("status %d body %v", r.status, r.body)
	}
	if delivered != 0 {
		t.Fatal("handed a notice to a Deliver that never said it sends them")
	}
}
