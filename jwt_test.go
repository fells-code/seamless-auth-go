package seamlessauth

import (
	"testing"
	"time"
)

func TestHS256RoundTrip(t *testing.T) {
	token, err := signHS256(map[string]any{"sub": "u1"}, testSecret, time.Minute, "k")
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyHS256(token, testSecret)
	if err != nil || claims["sub"] != "u1" {
		t.Fatalf("%v %v", claims, err)
	}
	if _, err := verifyHS256(token, "another-secret-another-secret-another"); err == nil {
		t.Fatal("verified under the wrong secret")
	}
	if _, err := verifyHS256(token[:len(token)-2]+"xx", testSecret); err == nil {
		t.Fatal("verified an altered signature")
	}
}

func TestHS256Expiry(t *testing.T) {
	token, _ := signHS256(map[string]any{"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix()}, testSecret, 0, "")
	if _, err := verifyHS256(token, testSecret); err == nil {
		t.Fatal("accepted an expired token")
	}
}

func TestHS256RefusesOtherAlgorithms(t *testing.T) {
	// A token claiming "none" must not verify, whatever its signature.
	if _, err := verifyHS256("eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1MSJ9.", testSecret); err == nil {
		t.Fatal("accepted alg none")
	}
}
