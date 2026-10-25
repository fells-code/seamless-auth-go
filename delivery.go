package seamlessauth

import (
	"encoding/json"
	"fmt"
)

// The kinds of message the auth API hands back.
const (
	DeliveryOTPEmail              = "otp_email"
	DeliveryOTPSMS                = "otp_sms"
	DeliveryMagicLinkEmail        = "magic_link_email"
	DeliveryEnrollmentInviteEmail = "enrollment_invite_email"
	DeliveryAccountNoticeEmail    = "account_notice_email"
	DeliveryAccountNoticeSMS      = "account_notice_sms"
)

// PurposeAccountRecovery marks a one-time code that recovers an account rather
// than signing in. Word it as a warning: someone asked to recover the account.
const PurposeAccountRecovery = "account_recovery"

var knownDeliveryKinds = set(
	DeliveryOTPEmail, DeliveryOTPSMS, DeliveryMagicLinkEmail, DeliveryEnrollmentInviteEmail,
	DeliveryAccountNoticeEmail, DeliveryAccountNoticeSMS,
)

// Delivery is a message the auth API hands back for the application to send.
type Delivery struct {
	// Kind is one of the Delivery* constants.
	Kind string
	// To is an email address or phone number.
	To string
	// Token is the one-time code, or the magic link's token.
	Token string
	// Purpose is PurposeAccountRecovery on a code that recovers an account, and
	// empty on a sign-in code.
	Purpose      string
	MagicLinkURL string
	SignInURL    string

	// Notice names what an account notice tells the owner, such as
	// account_recovery_opened.
	Notice string
	// Subject and Text are an account notice's message, written by the auth API.
	Subject string
	Text    string
	// CancelURL lets the owner stop an account recovery. It is a credential: send
	// it to To only, and never log it.
	CancelURL string
}

// String keeps the one-time credentials out of anything that prints a Delivery.
func (d Delivery) String() string {
	return fmt.Sprintf("Delivery{Kind: %s, To: %s, Notice: %s}", d.Kind, d.To, d.Notice)
}

// GoString is String, for %#v.
func (d Delivery) GoString() string {
	return d.String()
}

func parseDelivery(raw any) (Delivery, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return Delivery{}, fmt.Errorf("delivery is not an object")
	}

	d := Delivery{
		Kind:         stringClaim(obj, "kind"),
		To:           stringClaim(obj, "to"),
		Purpose:      stringClaim(obj, "purpose"),
		MagicLinkURL: stringClaim(obj, "magicLinkUrl"),
		SignInURL:    stringClaim(obj, "signInUrl"),
		Notice:       stringClaim(obj, "notice"),
		Subject:      stringClaim(obj, "subject"),
		Text:         stringClaim(obj, "text"),
		CancelURL:    stringClaim(obj, "cancelUrl"),
	}
	// An SMS code can arrive as a number.
	switch token := obj["token"].(type) {
	case string:
		d.Token = token
	case json.Number:
		d.Token = token.String()
	}

	if d.Kind == "" || d.To == "" {
		return Delivery{}, fmt.Errorf("delivery has no kind or recipient")
	}
	return d, nil
}
