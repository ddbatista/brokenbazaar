// Package auth is BrokenBazaar's hand-rolled JWT (HS256), stdlib only --
// crypto/hmac, crypto/sha256, encoding/base64, encoding/json, no third-party
// JWT library.
//
// Hand-rolled on purpose. AGENTS.md's house rule "hand-roll the mechanism when
// the mechanism is the lesson" names this exact case: a JWT library would make
// the alg:none and unverified-signature paths the *library's* bugs, so
// finding 02 would teach nothing. The verifier is product code here, and is
// read as product code. (D3 in threat-models/m1-tenancy.md fixes the format
// this package implements.)
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Issuer is the fixed `iss` claim (D3). TokenTTL is the window between `iat`
// and `exp` (D3: exp = iat + 3600). The handler stamps iat/exp; this package
// just owns the constants so there is one definition of "one hour".
const (
	Issuer   = "brokenbazaar"
	TokenTTL = time.Hour
	alg      = "HS256"
)

// Claims is D3's exact claim set, no more and no less. Note org_id: it is
// here because a real implementation puts it in the token to avoid a
// membership lookup per request -- and that convenience is the entire
// substrate of finding 02 (see M1-N5). The hardened request path resolves the
// acting org by server-side membership lookup (SR-B2-2) and does not trust
// this field; it is minted honestly (SR-B1-4) and must simply not be believed.
type Claims struct {
	Sub   string `json:"sub"`
	OrgID string `json:"org_id"`
	Role  string `json:"role"`
	Iss   string `json:"iss"`
	Iat   int64  `json:"iat"`
	Exp   int64  `json:"exp"`
}

var (
	ErrMalformedToken = errors.New("auth: token is not three base64url segments")
	ErrBadSignature   = errors.New("auth: signature does not verify")
	ErrExpired        = errors.New("auth: token has expired")
)

// b64 is base64url without padding -- the JWT wire encoding.
var b64 = base64.RawURLEncoding

// Encode always signs HS256. Header and payload are base64url(JSON); the
// signature is HMAC-SHA256 over "header.payload" with secret, base64url'd.
// There is no code path here that signs anything other than HS256 -- Encode
// is the honest issuer (SR-B1-4); the asymmetry this module teaches lives in
// Verify, not here.
func Encode(claims Claims, secret []byte) (string, error) {
	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}{Alg: alg, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("auth: marshaling header: %w", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshaling claims: %w", err)
	}
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	return signingInput + "." + b64.EncodeToString(sign(secret, signingInput)), nil
}

// Verify checks a token and returns its claims. The `hardened` flag selects
// between two verifiers that differ in exactly one decision -- whether the
// algorithm is chosen by this code or by the token -- and that one difference
// is the whole of finding 02.
//
// hardened=true (SR-B2-3): the algorithm is fixed at HS256 *in code*. The
// token's header is never decoded to decide what to do -- it is recomputed
// over, nothing more. The signature is checked with a constant-time compare
// and `exp` is enforced.
//
// hardened=false: the VULNERABLE verifier. DO NOT fix it. See the doc comment
// on verifyVulnerable below; it is the substrate finding 02 (attacks/02-jwt-
// org-claim, landing in T6) forges against, and AGENTS.md forbids repairing a
// planted vulnerability as a drive-by.
func Verify(token string, secret []byte, hardened bool) (Claims, error) {
	header, payload, sig, ok := split3(token)
	if !ok {
		return Claims{}, ErrMalformedToken
	}
	if hardened {
		return verifyHardened(header, payload, sig, secret)
	}
	return verifyVulnerable(header, payload, sig, secret)
}

// verifyHardened recomputes the HMAC over the token's own header.payload with
// our secret and compares constant-time. It never reads `alg` from the header:
// the header is attacker-controlled input, and a verifier that reads it to
// decide *whether or how* to verify is letting the attacker choose the check.
// SR-B2-3: fixed alg, `alg` never read from the token, expiry enforced.
func verifyHardened(header, payload, sig string, secret []byte) (Claims, error) {
	if !signatureEqual(secret, header+"."+payload, sig) {
		return Claims{}, ErrBadSignature
	}
	claims, err := decodeClaims(payload)
	if err != nil {
		return Claims{}, err
	}
	if time.Now().Unix() >= claims.Exp {
		return Claims{}, ErrExpired
	}
	return claims, nil
}

// verifyVulnerable is the planted vulnerability (B1 1.2, M1-N1's substrate).
// DO NOT fix it -- it is a documented departure from verifyHardened, written
// after the correct one on purpose (AGENTS.md: "write the correct
// implementation before the vulnerable one"), so finding 02's answer key can
// argue why a real developer writes it this way: they read `alg` out of the
// header because that is what the JWT spec literally says the field is for,
// and they special-case "none" because the spec defines it.
//
// The bug is the asymmetry: the code trusts attacker-controlled input (the
// header's `alg`) to decide whether to verify the signature at all. `alg:none`
// is accepted with NO signature check; any other `alg` still gets a real
// HMAC check. A forger therefore does not need the secret -- they set
// `alg:none`, write whatever claims they like (including an org_id for a
// tenant they do not belong to), and this verifier waves it through. That is
// finding 02 (attacks/02-jwt-org-claim, T6).
func verifyVulnerable(header, payload, sig string, secret []byte) (Claims, error) {
	var h struct {
		Alg string `json:"alg"`
	}
	raw, err := b64.DecodeString(header)
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return Claims{}, ErrMalformedToken
	}
	if h.Alg == "none" {
		// No signature check at all. This is the hole.
		return decodeClaims(payload)
	}
	if !signatureEqual(secret, header+"."+payload, sig) {
		return Claims{}, ErrBadSignature
	}
	return decodeClaims(payload)
}

// sign is HMAC-SHA256(secret, signingInput). One definition, used by both
// Encode and the verifiers so the signing input shape cannot drift between
// minting and checking.
func sign(secret []byte, signingInput string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// signatureEqual recomputes the expected signature and compares it with the
// presented one using crypto/subtle.ConstantTimeCompare, so a byte-by-byte
// timing oracle cannot be used to forge a signature one byte at a time. A
// signature segment that is not valid base64url fails closed.
func signatureEqual(secret []byte, signingInput, sig string) bool {
	presented, err := b64.DecodeString(sig)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(sign(secret, signingInput), presented) == 1
}

func decodeClaims(payload string) (Claims, error) {
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return Claims{}, ErrMalformedToken
	}
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		return Claims{}, ErrMalformedToken
	}
	return c, nil
}

// split3 splits a token into its header, payload and signature segments. A
// well-formed JWT is exactly two dots: anything else (one segment, four
// segments) is malformed and fails closed.
func split3(token string) (header, payload, sig string, ok bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", "", "", false
	}
	return parts[0], parts[1], parts[2], true
}
