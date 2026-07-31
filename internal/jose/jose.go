// Package jose decodes a JWS Compact Serialization token into its JOSE header
// and claim set. The jwtsvid and witsvid checkers both need this before they
// can evaluate their own spec clauses, so it lives here rather than being
// duplicated. Signature verification is out of scope.
package jose

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Decode splits a compact-serialized JWS and JSON-decodes its header and
// payload. The returned error describes the first structural problem found;
// callers map it onto the compact-serialization clause of their own spec.
func Decode(token string) (header, payload map[string]any, err error) {
	token = strings.TrimSpace(token)
	// Compact Serialization is exactly three Base64URL parts joined by ".".
	// JWS JSON Serialization is a JSON object, which starts with "{" and has
	// no such shape.
	parts := strings.Split(token, ".")
	if len(parts) != 3 || strings.HasPrefix(token, "{") {
		return nil, nil, fmt.Errorf("expected 3 dot-separated parts, got %d", len(parts))
	}
	if header, err = decodePart(parts[0]); err != nil {
		return nil, nil, fmt.Errorf("header decode: %w", err)
	}
	if payload, err = decodePart(parts[1]); err != nil {
		return nil, nil, fmt.Errorf("payload decode: %w", err)
	}
	return header, payload, nil
}

func decodePart(s string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		// Some encoders include padding; tolerate that case.
		raw, err = base64.URLEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// UnixClaim reads a numeric date claim (exp, nbf, iat) as a Unix timestamp.
// JSON numbers always decode to float64; the integer cases are for callers
// that assemble claim maps directly. name only phrases the error.
func UnixClaim(name string, v any) (int64, error) {
	switch x := v.(type) {
	case float64:
		return int64(x), nil
	case int64:
		return x, nil
	case int:
		return int64(x), nil
	default:
		return 0, fmt.Errorf("%s must be numeric, got %T", name, v)
	}
}
