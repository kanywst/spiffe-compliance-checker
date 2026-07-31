package jose_test

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/kanywst/spiffe-compliance-checker/internal/jose"
)

func TestDecode(t *testing.T) {
	raw := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	padded := func(s string) string { return base64.URLEncoding.EncodeToString([]byte(s)) }

	cases := []struct {
		name    string
		token   string
		wantErr string // substring; empty means success expected
	}{
		{
			name:  "raw base64url",
			token: raw(`{"alg":"ES256"}`) + "." + raw(`{"sub":"spiffe://example.com/a"}`) + ".sig",
		},
		{
			// Some encoders emit padded Base64URL; the decoder tolerates it.
			name:  "padded base64url",
			token: padded(`{"alg":"ES256"}`) + "." + padded(`{"sub":"spiffe://example.com/a"}`) + ".sig",
		},
		{
			name:  "surrounding whitespace trimmed",
			token: "  " + raw(`{"alg":"ES256"}`) + "." + raw(`{"sub":"x"}`) + ".sig\n",
		},
		{
			name:    "two parts",
			token:   raw(`{"alg":"ES256"}`) + "." + raw(`{}`),
			wantErr: "expected 3 dot-separated parts, got 2",
		},
		{
			// JWS JSON Serialization, which the SVID specs forbid.
			name:    "json serialization",
			token:   `{"protected":"a","payload":"b","signature":"c"}`,
			wantErr: "expected 3 dot-separated parts",
		},
		{
			name:    "header not base64",
			token:   "!!!." + raw(`{}`) + ".sig",
			wantErr: "header decode",
		},
		{
			name:    "header not json",
			token:   raw(`not json`) + "." + raw(`{}`) + ".sig",
			wantErr: "header decode",
		},
		{
			name:    "payload not json",
			token:   raw(`{"alg":"ES256"}`) + "." + raw(`[1,2,3]`) + ".sig",
			wantErr: "payload decode",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			header, payload, err := jose.Decode(tc.token)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("Decode() = nil error, want one mentioning %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Decode() error = %q, want it to mention %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Decode() error = %v, want nil", err)
			}
			if header == nil || payload == nil {
				t.Fatalf("Decode() = (%v, %v), want both non-nil", header, payload)
			}
		})
	}
}

func TestUnixClaim(t *testing.T) {
	// JSON always yields float64; the int cases exist for hand-built maps.
	for _, v := range []any{float64(1765456503), int64(1765456503), int(1765456503)} {
		got, err := jose.UnixClaim("exp", v)
		if err != nil {
			t.Fatalf("UnixClaim(%T) error = %v", v, err)
		}
		if got != 1765456503 {
			t.Errorf("UnixClaim(%T) = %d, want 1765456503", v, got)
		}
	}

	if _, err := jose.UnixClaim("nbf", "soon"); err == nil {
		t.Error("UnixClaim(string) = nil error, want a type error")
	} else if !strings.Contains(err.Error(), "nbf must be numeric") {
		t.Errorf("UnixClaim error = %q, want it to name the claim", err)
	}
}
