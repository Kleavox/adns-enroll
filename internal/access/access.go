package access

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	Header  = "Cf-Access-Jwt-Assertion"
	leeway  = time.Minute
	refetch = time.Minute
)

var ErrDenied = errors.New("not signed in")

type Verifier struct {
	Certs  string
	Issuer string
	AUD    string
	HTTP   *http.Client
	Now    func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

func New(team, aud string) *Verifier {
	team = strings.TrimSuffix(strings.TrimPrefix(team, "https://"), "/")
	return &Verifier{
		Certs:  "https://" + team + "/cdn-cgi/access/certs",
		Issuer: "https://" + team,
		AUD:    aud,
		HTTP:   &http.Client{Timeout: 10 * time.Second},
		Now:    time.Now,
	}
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

type payload struct {
	Audience  audience `json:"aud"`
	Email     string   `json:"email"`
	Issuer    string   `json:"iss"`
	Expires   *int64   `json:"exp"`
	NotBefore *int64   `json:"nbf"`
}

func decode(part string, into any) error {
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

func (v *Verifier) Email(r *http.Request) (string, error) {
	parts := strings.Split(r.Header.Get(Header), ".")
	if len(parts) != 3 {
		return "", ErrDenied
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if decode(parts[0], &header) != nil || header.Alg != "RS256" || header.Kid == "" {
		return "", ErrDenied
	}
	key, err := v.key(r.Context(), header.Kid)
	if err != nil {
		return "", ErrDenied
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", ErrDenied
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature) != nil {
		return "", ErrDenied
	}
	var c payload
	if decode(parts[1], &c) != nil {
		return "", ErrDenied
	}
	now := v.Now()
	switch {
	case c.Issuer != v.Issuer,
		!slices.Contains(c.Audience, v.AUD),
		c.Expires == nil || now.After(time.Unix(*c.Expires, 0).Add(leeway)),
		c.NotBefore != nil && now.Add(leeway).Before(time.Unix(*c.NotBefore, 0)),
		strings.TrimSpace(c.Email) == "":
		return "", ErrDenied
	}
	return strings.ToLower(strings.TrimSpace(c.Email)), nil
}

func (v *Verifier) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if key, found := v.keys[kid]; found {
		return key, nil
	}
	if !v.fetched.IsZero() && v.Now().Sub(v.fetched) < refetch {
		return nil, ErrDenied
	}
	v.fetched = v.Now()
	keys, err := v.fetch(ctx)
	if err != nil {
		return nil, err
	}
	v.keys = keys
	if key, found := keys[kid]; found {
		return key, nil
	}
	return nil, ErrDenied
}

func (v *Verifier) fetch(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.Certs, nil)
	if err != nil {
		return nil, err
	}
	response, err := v.HTTP.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("access certificates answered %d", response.StatusCode)
	}
	var listed struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&listed); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, entry := range listed.Keys {
		if entry.Kty != "RSA" || entry.Kid == "" {
			continue
		}
		n, errN := base64.RawURLEncoding.DecodeString(entry.N)
		e, errE := base64.RawURLEncoding.DecodeString(entry.E)
		if errN != nil || errE != nil || len(e) == 0 || len(e) > 4 {
			continue
		}
		keys[entry.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	}
	return keys, nil
}
