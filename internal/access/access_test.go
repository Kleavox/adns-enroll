package access

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)

type keys struct {
	signing *rsa.PrivateKey
	other   *rsa.PrivateKey
	fetches atomic.Int32
	served  []jwk
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func publicJWK(kid string, key *rsa.PublicKey) jwk {
	return jwk{Kid: kid, Kty: "RSA", Alg: "RS256", N: base64.RawURLEncoding.EncodeToString(key.N.Bytes()), E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}
}

func setup(t *testing.T) (*Verifier, *keys) {
	t.Helper()
	signing, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	k := &keys{signing: signing, other: other, served: []jwk{publicJWK("k1", &signing.PublicKey)}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		k.fetches.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": k.served})
	}))
	t.Cleanup(server.Close)
	verifier := &Verifier{Certs: server.URL, Issuer: "https://kleavox.cloudflareaccess.com", AUD: "aud-123", HTTP: server.Client(), Now: func() time.Time { return now }}
	return verifier, k
}

func token(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	signed := encode(header) + "." + encode(claims)
	sum := sha256.Sum256([]byte(signed))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func claims(change func(map[string]any)) map[string]any {
	values := map[string]any{
		"aud":   []string{"aud-123"},
		"email": "Owner@Example.com",
		"iss":   "https://kleavox.cloudflareaccess.com",
		"exp":   now.Add(time.Hour).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"type":  "app",
	}
	if change != nil {
		change(values)
	}
	return values
}

func request(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if value != "" {
		r.Header.Set("Cf-Access-Jwt-Assertion", value)
	}
	return r
}

var header = map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"}

func TestAValidTokenNamesThePerson(t *testing.T) {
	verifier, k := setup(t)
	email, err := verifier.Email(request(token(t, k.signing, header, claims(nil))))
	if err != nil || email != "owner@example.com" {
		t.Fatalf("email %q err %v", email, err)
	}
	single := claims(func(values map[string]any) { values["aud"] = "aud-123" })
	if _, err := verifier.Email(request(token(t, k.signing, header, single))); err != nil {
		t.Fatalf("a single audience string is valid too: %v", err)
	}
	if k.fetches.Load() != 1 {
		t.Fatalf("keys are fetched once, not per request: %d", k.fetches.Load())
	}
}

func TestEverythingElseIsRefused(t *testing.T) {
	verifier, k := setup(t)
	for name, value := range map[string]string{
		"missing":         "",
		"garbage":         "not.a.token",
		"two parts":       "a.b",
		"other key":       token(t, k.other, header, claims(nil)),
		"wrong audience":  token(t, k.signing, header, claims(func(v map[string]any) { v["aud"] = []string{"someone-else"} })),
		"wrong issuer":    token(t, k.signing, header, claims(func(v map[string]any) { v["iss"] = "https://evil.cloudflareaccess.com" })),
		"expired":         token(t, k.signing, header, claims(func(v map[string]any) { v["exp"] = now.Add(-2 * time.Minute).Unix() })),
		"not yet":         token(t, k.signing, header, claims(func(v map[string]any) { v["nbf"] = now.Add(2 * time.Minute).Unix() })),
		"no email":        token(t, k.signing, header, claims(func(v map[string]any) { delete(v, "email") })),
		"no expiry":       token(t, k.signing, header, claims(func(v map[string]any) { delete(v, "exp") })),
		"other algorithm": token(t, k.signing, map[string]any{"alg": "HS256", "kid": "k1"}, claims(nil)),
		"none":            token(t, k.signing, map[string]any{"alg": "none", "kid": "k1"}, claims(nil)),
		"unknown key":     token(t, k.signing, map[string]any{"alg": "RS256", "kid": "k9"}, claims(nil)),
	} {
		if email, err := verifier.Email(request(value)); err == nil {
			t.Errorf("%s was taken as %q", name, email)
		}
	}
	forged := token(t, k.signing, header, claims(nil))
	parts := strings.Split(forged, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"aud":["aud-123"],"email":"admin@example.com","iss":"https://kleavox.cloudflareaccess.com","exp":9999999999}`))
	if _, err := verifier.Email(request(strings.Join(parts, "."))); err == nil {
		t.Error("a changed payload must fail the signature")
	}
}

func TestARotatedKeyIsFetchedButNotOnEveryUnknownKey(t *testing.T) {
	verifier, k := setup(t)
	if _, err := verifier.Email(request(token(t, k.signing, header, claims(nil)))); err != nil {
		t.Fatal(err)
	}
	k.served = append(k.served, publicJWK("k2", &k.other.PublicKey))
	rotated := token(t, k.other, map[string]any{"alg": "RS256", "kid": "k2"}, claims(nil))
	verifier.Now = func() time.Time { return now.Add(2 * time.Minute) }
	if _, err := verifier.Email(request(rotated)); err != nil {
		t.Fatalf("a new key is fetched: %v", err)
	}
	unknown := token(t, k.other, map[string]any{"alg": "RS256", "kid": "k7"}, claims(nil))
	before := k.fetches.Load()
	for range 5 {
		verifier.Email(request(unknown))
	}
	if k.fetches.Load() > before+1 {
		t.Fatalf("unknown keys must not hammer Cloudflare: %d fetches", k.fetches.Load()-before)
	}
}

func TestTheCertificatesAddressFollowsTheTeam(t *testing.T) {
	verifier := New("kleavox.cloudflareaccess.com", "aud-123")
	if verifier.Certs != "https://kleavox.cloudflareaccess.com/cdn-cgi/access/certs" || verifier.Issuer != "https://kleavox.cloudflareaccess.com" {
		t.Fatalf("verifier %#v", verifier)
	}
}
