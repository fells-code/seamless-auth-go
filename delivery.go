package seamlessauth

import (
	"encoding/json"
	"fmt"
)

// Delivery is a message the auth API hands back for the application to send.
type Delivery struct {
	// Kind is otp_email, otp_sms, magic_link_email or enrollment_invite_email.
	Kind string
	// To is an email address or phone number.
	To string
	// Token is the one-time code, or the magic link's token.
	Token        string
	MagicLinkURL string
	SignInURL    string
}

func parseDelivery(raw any) (Delivery, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return Delivery{}, fmt.Errorf("delivery is not an object")
	}

	d := Delivery{
		Kind:         stringClaim(obj, "kind"),
		To:           stringClaim(obj, "to"),
		MagicLinkURL: stringClaim(obj, "magicLinkUrl"),
		SignInURL:    stringClaim(obj, "signInUrl"),
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
