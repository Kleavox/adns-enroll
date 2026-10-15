package pawl

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	CardUse = "pawl-card"
	leeway  = time.Minute
	refetch = time.Minute
	scope   = "openid email profile"
)

var ErrDenied = errors.New("not signed by Pawl for this app")

type Person struct {
	Sub   string
	Email string
	Name  string
}

type Provider struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURI  string
	HTTP         *http.Client
	Now          func() time.Time

	mu      sync.Mutex
	meta    *metadata
	keys    map[string]*ecdsa.PublicKey
	fetched time.Time
}

type metadata struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	JWKS          string `json:"jwks_uri"`
	Subjects      string `json:"pawl_subjects_endpoint"`
}

func New(issuer, clientID, secret, redirectURI string) *Provider {
	return &Provider{
		Issuer:       strings.TrimSuffix(issuer, "/"),
		ClientID:     clientID,
		ClientSecret: secret,
		RedirectURI:  redirectURI,
		HTTP:         &http.Client{Timeout: 10 * time.Second},
		Now:          time.Now,
	}
}

func Random() string {
	buffer := make([]byte, 32)
	rand.Read(buffer)
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (p *Provider) get(ctx context.Context, address string, into any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	return p.do(request, into)
}

func (p *Provider) do(request *http.Request, into any) error {
	response, err := p.HTTP.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("pawl %s answered %d", request.URL.Path, response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(into)
}

func (p *Provider) discover(ctx context.Context) (*metadata, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.meta != nil {
		return p.meta, nil
	}
	var meta metadata
	if err := p.get(ctx, p.Issuer+"/.well-known/openid-configuration", &meta); err != nil {
		return nil, err
	}
	if meta.Issuer != p.Issuer || meta.Authorization == "" || meta.Token == "" || meta.JWKS == "" {
		return nil, errors.New("pawl's discovery document does not name this issuer and its endpoints")
	}
	p.meta = &meta
	return p.meta, nil
}

func (p *Provider) AuthorizeURL(ctx context.Context, state, nonce, challenge string) (string, error) {
	meta, err := p.discover(ctx)
	if err != nil {
		return "", err
	}
	target, err := url.Parse(meta.Authorization)
	if err != nil {
		return "", err
	}
	query := target.Query()
	for name, value := range map[string]string{
		"client_id":             p.ClientID,
		"redirect_uri":          p.RedirectURI,
		"response_type":         "code",
		"scope":                 scope,
		"state":                 state,
		"nonce":                 nonce,
		"code_challenge":        challenge,
		"code_challenge_method": "S256",
	} {
		query.Set(name, value)
	}
	target.RawQuery = query.Encode()
	return target.String(), nil
}

func escape(value string) string {
	return strings.ReplaceAll(url.QueryEscape(value), "+", "%20")
}

func (p *Provider) authorize(request *http.Request) {
	request.SetBasicAuth(escape(p.ClientID), escape(p.ClientSecret))
}

func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Person, error) {
	meta, err := p.discover(ctx)
	if err != nil {
		return Person{}, err
	}
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.RedirectURI},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.Token, strings.NewReader(form.Encode()))
	if err != nil {
		return Person{}, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	p.authorize(request)
	var tokens struct {
		IDToken string `json:"id_token"`
	}
	if err := p.do(request, &tokens); err != nil {
		return Person{}, err
	}
	return p.verify(ctx, tokens.IDToken, func(c claims) bool {
		return c.Use == "" && nonce != "" && c.Nonce == nonce
	})
}

func (p *Provider) Card(ctx context.Context, token string) (Person, error) {
	return p.verify(ctx, token, func(c claims) bool {
		return c.Use == CardUse && c.Nonce == ""
	})
}

func (p *Provider) Live(ctx context.Context, subjects []string) ([]string, error) {
	meta, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}
	if meta.Subjects == "" {
		return nil, errors.New("pawl does not say which subjects are still connected")
	}
	body, err := json.Marshal(map[string][]string{"subjects": subjects})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.Subjects, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	p.authorize(request)
	var answer struct {
		Live *[]string `json:"live"`
	}
	if err := p.do(request, &answer); err != nil {
		return nil, err
	}
	if answer.Live == nil {
		return nil, errors.New("pawl's answer names no live subjects")
	}
	return *answer.Live, nil
}

type audience []string

func (a *audience) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

type claims struct {
	Issuer   string   `json:"iss"`
	Audience audience `json:"aud"`
	Subject  string   `json:"sub"`
	Email    string   `json:"email"`
	Verified bool     `json:"email_verified"`
	Name     string   `json:"preferred_username"`
	Nonce    string   `json:"nonce"`
	Use      string   `json:"token_use"`
	Expires  *int64   `json:"exp"`
	Issued   *int64   `json:"iat"`
}

func decode(part string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (p *Provider) verify(ctx context.Context, token string, meant func(claims) bool) (Person, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Person{}, ErrDenied
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if decode(parts[0], &header) != nil || header.Alg != "ES256" || header.Kid == "" {
		return Person{}, ErrDenied
	}
	meta, err := p.discover(ctx)
	if err != nil {
		return Person{}, err
	}
	key, err := p.key(ctx, meta, header.Kid)
	if err != nil {
		return Person{}, ErrDenied
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != 64 {
		return Person{}, ErrDenied
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	if !ecdsa.Verify(key, sum[:], r, s) {
		return Person{}, ErrDenied
	}
	var c claims
	if decode(parts[1], &c) != nil {
		return Person{}, ErrDenied
	}
	now := p.Now()
	switch {
	case c.Issuer != meta.Issuer,
		!slices.Contains(c.Audience, p.ClientID),
		strings.TrimSpace(c.Subject) == "",
		c.Expires == nil || now.After(time.Unix(*c.Expires, 0).Add(leeway)),
		c.Issued != nil && now.Add(leeway).Before(time.Unix(*c.Issued, 0)),
		!meant(c):
		return Person{}, ErrDenied
	}
	person := Person{Sub: c.Subject, Name: strings.TrimSpace(c.Name)}
	if c.Verified {
		person.Email = strings.ToLower(strings.TrimSpace(c.Email))
	}
	return person, nil
}

func (p *Provider) key(ctx context.Context, meta *metadata, kid string) (*ecdsa.PublicKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if key, found := p.keys[kid]; found {
		return key, nil
	}
	if !p.fetched.IsZero() && p.Now().Sub(p.fetched) < refetch {
		return nil, ErrDenied
	}
	p.fetched = p.Now()
	var listed struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := p.get(ctx, meta.JWKS, &listed); err != nil {
		return nil, err
	}
	keys := map[string]*ecdsa.PublicKey{}
	for _, entry := range listed.Keys {
		if entry.Kty != "EC" || entry.Crv != "P-256" || entry.Kid == "" {
			continue
		}
		x, errX := base64.RawURLEncoding.DecodeString(entry.X)
		y, errY := base64.RawURLEncoding.DecodeString(entry.Y)
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			continue
		}
		key, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			continue
		}
		keys[entry.Kid] = key
	}
	p.keys = keys
	if key, found := keys[kid]; found {
		return key, nil
	}
	return nil, ErrDenied
}
