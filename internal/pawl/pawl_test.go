package pawl

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

type fake struct {
	server      *httptest.Server
	key         *ecdsa.PrivateKey
	kid         string
	jwksFetches int
	tokenForms  []url.Values
	tokenAuth   []string
	idToken     string
	live        []string
	liveStatus  int
	asked       []string
	noSubjects  bool
}

func newFake(t *testing.T) *fake {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{key: key, kid: "k1", liveStatus: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		issuer := f.server.URL
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			meta := map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/oauth/authorize",
				"token_endpoint":         issuer + "/oauth/token",
				"jwks_uri":               issuer + "/oauth/jwks.json",
			}
			if !f.noSubjects {
				meta["pawl_subjects_endpoint"] = issuer + "/oauth/subjects"
			}
			json.NewEncoder(w).Encode(meta)
		case "/oauth/jwks.json":
			f.jwksFetches++
			point, _ := f.key.PublicKey.ECDH()
			raw := point.Bytes()
			json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
				"x": base64.RawURLEncoding.EncodeToString(raw[1:33]),
				"y": base64.RawURLEncoding.EncodeToString(raw[33:]),
			}}})
		case "/oauth/token":
			r.ParseForm()
			f.tokenForms = append(f.tokenForms, r.PostForm)
			f.tokenAuth = append(f.tokenAuth, r.Header.Get("Authorization"))
			json.NewEncoder(w).Encode(map[string]any{"id_token": f.idToken, "access_token": "a", "token_type": "Bearer"})
		case "/oauth/subjects":
			f.tokenAuth = append(f.tokenAuth, r.Header.Get("Authorization"))
			var body struct {
				Subjects []string `json:"subjects"`
			}
			json.NewDecoder(r.Body).Decode(&body)
			f.asked = append(f.asked, body.Subjects...)
			w.WriteHeader(f.liveStatus)
			json.NewEncoder(w).Encode(map[string]any{"live": f.live})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fake) sign(t *testing.T, claims map[string]any, kid string) string {
	t.Helper()
	encode := func(value any) string {
		raw, _ := json.Marshal(value)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	input := encode(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid}) + "." + encode(claims)
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, f.key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(signature)
}

var now = time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)

func (f *fake) claims(extra map[string]any) map[string]any {
	claims := map[string]any{
		"iss":                f.server.URL,
		"aud":                "dns",
		"sub":                "pairwise-budi",
		"email":              "budi@example.com",
		"email_verified":     true,
		"preferred_username": "budi",
		"iat":                now.Unix(),
		"exp":                now.Add(time.Minute).Unix(),
	}
	for name, value := range extra {
		if value == nil {
			delete(claims, name)
		} else {
			claims[name] = value
		}
	}
	return claims
}

func provider(f *fake) *Provider {
	p := New(f.server.URL, "dns", "the secret", "https://enroll.example.test/auth/callback")
	p.HTTP = f.server.Client()
	p.Now = func() time.Time { return now }
	return p
}

var ctx = context.Background()

func TestTheSignInAddressAsksPawlWithPKCEStateAndNonce(t *testing.T) {
	f := newFake(t)
	address, err := provider(f).AuthorizeURL(ctx, "the-state", "the-nonce", Challenge("the-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(address)
	query := target.Query()
	if target.Path != "/oauth/authorize" || query.Get("client_id") != "dns" || query.Get("response_type") != "code" ||
		query.Get("redirect_uri") != "https://enroll.example.test/auth/callback" || query.Get("scope") != "openid email profile" ||
		query.Get("state") != "the-state" || query.Get("nonce") != "the-nonce" || query.Get("code_challenge_method") != "S256" ||
		query.Get("code_challenge") != Challenge("the-verifier") {
		t.Fatalf("address %s", address)
	}
	if len(Challenge("the-verifier")) != 43 || len(Random()) < 43 || Random() == Random() {
		t.Fatal("weak challenge or random values")
	}
}

func TestACodeBecomesThePersonPawlSigned(t *testing.T) {
	f := newFake(t)
	f.idToken = f.sign(t, f.claims(map[string]any{"nonce": "the-nonce"}), "k1")
	person, err := provider(f).Exchange(ctx, "the-code", "the-verifier", "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if person.Sub != "pairwise-budi" || person.Email != "budi@example.com" || person.Name != "budi" {
		t.Fatalf("person %#v", person)
	}
	form := f.tokenForms[0]
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" || form.Get("code_verifier") != "the-verifier" ||
		form.Get("redirect_uri") != "https://enroll.example.test/auth/callback" || form.Get("client_secret") != "" {
		t.Fatalf("form %v", form)
	}
	if f.tokenAuth[0] != "Basic "+base64.StdEncoding.EncodeToString([]byte("dns:the%20secret")) {
		t.Fatalf("auth %q", f.tokenAuth[0])
	}
}

func TestAnIDTokenThatIsNotForThisSignInIsRefused(t *testing.T) {
	cases := map[string]map[string]any{
		"another nonce":   {"nonce": "other"},
		"no nonce":        {},
		"another app":     {"nonce": "the-nonce", "aud": "other"},
		"another issuer":  {"nonce": "the-nonce", "iss": "https://evil.test"},
		"expired":         {"nonce": "the-nonce", "exp": now.Add(-2 * time.Minute).Unix()},
		"no subject":      {"nonce": "the-nonce", "sub": nil},
		"a card token":    {"nonce": "the-nonce", "token_use": "pawl-card"},
		"from the future": {"nonce": "the-nonce", "iat": now.Add(10 * time.Minute).Unix()},
	}
	for name, change := range cases {
		f := newFake(t)
		f.idToken = f.sign(t, f.claims(change), "k1")
		if _, err := provider(f).Exchange(ctx, "c", "v", "the-nonce"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	f := newFake(t)
	stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.key, f.idToken = stranger, ""
	forged := f.sign(t, f.claims(map[string]any{"nonce": "the-nonce"}), "k1")
	f.key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.idToken = forged
	if _, err := provider(f).Exchange(ctx, "c", "v", "the-nonce"); err == nil {
		t.Error("a token signed by another key was accepted")
	}
}

func TestACardRequestIsAcceptedOnlyAsACardRequest(t *testing.T) {
	f := newFake(t)
	p := provider(f)
	card := f.sign(t, f.claims(map[string]any{"token_use": "pawl-card"}), "k1")
	person, err := p.Card(ctx, card)
	if err != nil || person.Sub != "pairwise-budi" || person.Email != "budi@example.com" {
		t.Fatalf("person %#v err %v", person, err)
	}
	for name, token := range map[string]string{
		"an id token":   f.sign(t, f.claims(map[string]any{"nonce": "n"}), "k1"),
		"no use":        f.sign(t, f.claims(nil), "k1"),
		"another app":   f.sign(t, f.claims(map[string]any{"token_use": "pawl-card", "aud": "other"}), "k1"),
		"expired":       f.sign(t, f.claims(map[string]any{"token_use": "pawl-card", "exp": now.Add(-2 * time.Minute).Unix()}), "k1"),
		"not a token":   "a.b",
		"empty":         "",
		"tampered body": strings.Replace(card, ".", ".x", 1),
	} {
		if _, err := p.Card(ctx, token); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestAnUnknownKeyIsLookedUpOnceAMinuteAtMost(t *testing.T) {
	f := newFake(t)
	p := provider(f)
	unknown := f.sign(t, f.claims(map[string]any{"token_use": "pawl-card"}), "k2")
	for range 3 {
		if _, err := p.Card(ctx, unknown); err == nil {
			t.Fatal("an unknown key was accepted")
		}
	}
	if f.jwksFetches != 1 {
		t.Fatalf("fetched the keys %d times", f.jwksFetches)
	}
}

func TestPawlSaysWhichSubjectsAreStillConnected(t *testing.T) {
	f := newFake(t)
	f.live = []string{"a"}
	live, err := provider(f).Live(ctx, []string{"a", "b"})
	if err != nil || !slices.Equal(live, []string{"a"}) || !slices.Equal(f.asked, []string{"a", "b"}) {
		t.Fatalf("live %v asked %v err %v", live, f.asked, err)
	}
	if !strings.HasPrefix(f.tokenAuth[0], "Basic ") {
		t.Fatalf("auth %q", f.tokenAuth[0])
	}
	f.liveStatus = http.StatusServiceUnavailable
	if _, err := provider(f).Live(ctx, []string{"a"}); err == nil {
		t.Fatal("a failed answer reads as an answer")
	}
	g := newFake(t)
	g.noSubjects = true
	if _, err := provider(g).Live(ctx, []string{"a"}); err == nil {
		t.Fatal("a Pawl without the endpoint reads as an answer")
	}
}
