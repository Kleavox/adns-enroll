package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookie = "__Host-adns"
	signinCookie  = "__Host-adns-signin"
	sessionFor    = 12 * time.Hour
	signinFor     = 10 * time.Minute
	useSession    = "session"
	useSignin     = "signin"
)

type sealed struct {
	Use      string `json:"use"`
	Sub      string `json:"sub,omitempty"`
	Email    string `json:"email,omitempty"`
	Name     string `json:"name,omitempty"`
	State    string `json:"state,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
	Verifier string `json:"verifier,omitempty"`
	Expires  int64  `json:"exp"`
}

func (s *Server) mac(body string) []byte {
	signer := hmac.New(sha256.New, s.Key)
	signer.Write([]byte(body))
	return signer.Sum(nil)
}

func (s *Server) seal(value sealed) string {
	raw, _ := json.Marshal(value)
	body := base64.RawURLEncoding.EncodeToString(raw)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(body))
}

func (s *Server) open(text, use string) (sealed, bool) {
	body, signature, found := strings.Cut(text, ".")
	if !found {
		return sealed{}, false
	}
	given, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !hmac.Equal(given, s.mac(body)) {
		return sealed{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return sealed{}, false
	}
	var value sealed
	if json.Unmarshal(raw, &value) != nil || value.Use != use || s.Now().Unix() >= value.Expires {
		return sealed{}, false
	}
	return value, true
}

func (s *Server) keep(w http.ResponseWriter, name string, value sealed, lasting time.Duration) {
	value.Expires = s.Now().Add(lasting).Unix()
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    s.seal(value),
		Path:     "/",
		MaxAge:   int(lasting / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func forget(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) read(r *http.Request, name, use string) (sealed, bool) {
	cookie, err := r.Cookie(name)
	if err != nil {
		return sealed{}, false
	}
	return s.open(cookie.Value, use)
}
