package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/pawl"
	"github.com/Kleavox/adns-enroll/internal/store"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static
var static embed.FS

var pages = template.Must(template.ParseFS(templates, "templates/*.html"))

const policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

type Pawl interface {
	AuthorizeURL(ctx context.Context, state, nonce, challenge string) (string, error)
	Exchange(ctx context.Context, code, verifier, nonce string) (pawl.Person, error)
	Card(ctx context.Context, token string) (pawl.Person, error)
}

type AdGuard interface {
	Encryption(ctx context.Context) (adguard.Encryption, error)
	QueryLog(ctx context.Context) (bool, error)
}

type Server struct {
	Service *enroll.Service
	AdGuard AdGuard
	Pawl    Pawl
	Admins  []string
	Origin  string
	Key     []byte
	Missing string
	Log     func(format string, args ...any)
	Now     func() time.Time
}

var notices = map[string]string{
	"approved": "Approved. Their address works now.",
	"rejected": "Rejected.",
	"revoked":  "Revoked. Their address has stopped working.",
	"renewed":  "They have a new address; the old one has stopped working. Let them know.",
	"linked":   "Linked. They keep the addresses they had before.",
}

type row struct {
	ID        string
	Email     string
	Name      string
	Status    string
	Label     string
	Requested time.Time
	Legacy    string
}

type page struct {
	Template    string
	Email       string
	Admin       bool
	Status      string
	Address     string
	PrivateDNS  string
	Unavailable string
	ClientID    string
	LogNote     bool
	Sub         string
	NoAdmin     bool
	Notice      string
	Problem     string
	Heading     string
	Message     string
	Waiting     []row
	Accounts    []row
	Denied      []row
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(static, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /auth/signin", s.ready(s.signin))
	mux.HandleFunc("GET /auth/callback", s.ready(s.callback))
	mux.HandleFunc("POST /auth/signout", s.ready(s.signout))
	mux.HandleFunc("GET /.well-known/pawl/card", s.ready(s.card))
	mux.HandleFunc("GET /{$}", s.ready(s.person(s.home)))
	for _, action := range []string{"approve", "reject", "revoke", "renew", "link"} {
		mux.HandleFunc("POST /admin/accounts/{id}/"+action, s.ready(s.person(s.change(s.admin(s.decide(action))))))
	}
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", policy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) ready(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Missing != "" {
			http.Error(w, "Sign-in is not set up yet: "+s.Missing+" is missing.", http.StatusServiceUnavailable)
			return
		}
		next(w, r)
	}
}

type handler func(w http.ResponseWriter, r *http.Request, who sealed)

func (s *Server) person(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, found := s.read(r, sessionCookie, useSession)
		if !found {
			http.Redirect(w, r, "/auth/signin", http.StatusFound)
			return
		}
		next(w, r, who)
	}
}

func (s *Server) sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	from, err := url.Parse(r.Header.Get("Origin"))
	if err != nil || from.Host == "" || (from.Scheme != "https" && from.Scheme != "http") {
		return false
	}
	return from.Host == r.Host || from.Scheme+"://"+from.Host == s.Origin
}

func (s *Server) change(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, who sealed) {
		if !s.sameOrigin(r) {
			http.Error(w, "This change has to come from this site.", http.StatusForbidden)
			return
		}
		next(w, r, who)
	}
}

func (s *Server) isAdmin(sub string) bool {
	return sub != "" && slices.Contains(s.Admins, sub)
}

func (s *Server) admin(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, who sealed) {
		if !s.isAdmin(who.Sub) {
			http.Error(w, "Only an admin can do this.", http.StatusForbidden)
			return
		}
		next(w, r, who)
	}
}

func (s *Server) render(w http.ResponseWriter, status int, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, "layout", data); err != nil {
		s.Log("render %s: %v", data.Template, err)
	}
}

func (s *Server) message(w http.ResponseWriter, status int, heading, message string) {
	s.render(w, status, page{Template: "message", Heading: heading, Message: message})
}

func (s *Server) signin(w http.ResponseWriter, r *http.Request) {
	state, nonce, verifier := pawl.Random(), pawl.Random(), pawl.Random()
	address, err := s.Pawl.AuthorizeURL(r.Context(), state, nonce, pawl.Challenge(verifier))
	if err != nil {
		s.Log("sign-in: %v", err)
		s.message(w, http.StatusBadGateway, "Pawl cannot be reached", "Sign-in goes through Pawl, which is not answering right now. Try again in a moment.")
		return
	}
	s.keep(w, signinCookie, sealed{Use: useSignin, State: state, Nonce: nonce, Verifier: verifier}, signinFor)
	http.Redirect(w, r, address, http.StatusFound)
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	started, found := s.read(r, signinCookie, useSignin)
	forget(w, signinCookie)
	if query.Get("error") != "" {
		s.message(w, http.StatusUnauthorized, "Sign-in was cancelled", "Nothing was shared.")
		return
	}
	if !found || query.Get("state") == "" || query.Get("state") != started.State {
		s.message(w, http.StatusBadRequest, "This sign-in has expired", "It was started in another tab or too long ago.")
		return
	}
	person, err := s.Pawl.Exchange(r.Context(), query.Get("code"), started.Verifier, started.Nonce)
	if err != nil {
		s.Log("sign-in: %v", err)
		s.message(w, http.StatusUnauthorized, "Pawl did not confirm who you are", "Nothing was shared.")
		return
	}
	if _, err := s.Service.Seen(r.Context(), enroll.Person{Sub: person.Sub, Email: person.Email, Name: person.Name}); err != nil {
		s.Log("sign-in for %s: %v", person.Email, err)
		s.message(w, http.StatusInternalServerError, "Your account could not be read", "Try again in a moment.")
		return
	}
	s.keep(w, sessionCookie, sealed{Use: useSession, Sub: person.Sub, Email: person.Email, Name: person.Name}, sessionFor)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) signout(w http.ResponseWriter, r *http.Request) {
	if !s.sameOrigin(r) {
		http.Error(w, "This change has to come from this site.", http.StatusForbidden)
		return
	}
	forget(w, sessionCookie)
	s.message(w, http.StatusOK, "Signed out of Private DNS", "Your Pawl session stays as it is.")
}

const (
	notAnswering = "AdGuard is not answering, so your address cannot be shown right now."
	noEncryption = "AdGuard has no encrypted DNS turned on, so there is no address to use yet."
)

type addresses struct {
	DoH        string
	PrivateDNS string
	Problem    string
}

func (s *Server) addressesFor(ctx context.Context, account store.Account) addresses {
	if account.Status != store.Approved || len(account.ClientIDs) == 0 {
		return addresses{}
	}
	encryption, err := s.AdGuard.Encryption(ctx)
	if err != nil {
		s.Log("read AdGuard's encryption settings: %v", err)
		return addresses{Problem: notAnswering}
	}
	id := account.ClientIDs[0]
	found := addresses{DoH: encryption.DoH(id), PrivateDNS: encryption.PrivateDNS(id)}
	if found.DoH == "" {
		found.Problem = noEncryption
	}
	return found
}

func (s *Server) lookupsLogged(ctx context.Context) bool {
	logged, err := s.AdGuard.QueryLog(ctx)
	if err != nil {
		s.Log("read AdGuard's query log setting: %v", err)
		return true
	}
	return logged
}

func label(account store.Account) string {
	switch {
	case account.Status == store.Approved && account.Sub == "":
		return "From before Pawl"
	case account.Status == store.Approved:
		return "Active"
	case account.Status == store.Ended:
		return "Gone from Pawl"
	case account.Status == store.Waiting:
		return "Waiting for approval"
	}
	return "No access"
}

func (s *Server) homePage(r *http.Request, who sealed) (page, error) {
	state, err := s.Service.Store.Read()
	if err != nil {
		return page{}, err
	}
	data := page{Template: "person", Email: who.Email, Sub: who.Sub, Admin: s.isAdmin(who.Sub), NoAdmin: len(s.Admins) == 0, Status: string(store.Waiting), Notice: notices[r.URL.Query().Get("done")]}
	for _, account := range state.Accounts {
		if account.Sub == who.Sub {
			data.Status = string(account.Status)
			if account.Status == store.Approved && len(account.ClientIDs) > 0 {
				found := s.addressesFor(r.Context(), account)
				data.Address, data.PrivateDNS, data.Unavailable, data.ClientID = found.DoH, found.PrivateDNS, found.Problem, account.ClientIDs[0]
			}
		}
	}
	if data.Address != "" && !data.Admin {
		data.LogNote = s.lookupsLogged(r.Context())
	}
	if data.Admin {
		data.Template = "admin"
		legacy := map[string]string{}
		for _, account := range state.Accounts {
			if account.Sub == "" && account.Status == store.Approved {
				legacy[account.Email] = account.ID
			}
		}
		for _, account := range state.Accounts {
			shown := row{ID: account.ID, Email: account.Email, Name: account.Name, Status: string(account.Status), Label: label(account), Requested: account.Requested}
			switch account.Status {
			case store.Waiting:
				shown.Legacy = legacy[account.Email]
				data.Waiting = append(data.Waiting, shown)
			case store.Denied:
				data.Denied = append(data.Denied, shown)
			default:
				data.Accounts = append(data.Accounts, shown)
			}
		}
	}
	return data, nil
}

func (s *Server) home(w http.ResponseWriter, r *http.Request, who sealed) {
	data, err := s.homePage(r, who)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, data)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log("store: %v", err)
	http.Error(w, "The account list could not be read.", http.StatusInternalServerError)
}

func (s *Server) decide(action string) handler {
	return func(w http.ResponseWriter, r *http.Request, who sealed) {
		id := r.PathValue("id")
		var err error
		switch action {
		case "approve":
			err = s.Service.Approve(r.Context(), id)
		case "reject":
			err = s.Service.Reject(id)
		case "revoke":
			err = s.Service.Revoke(r.Context(), id)
		case "renew":
			err = s.Service.Renew(r.Context(), id)
		case "link":
			err = s.Service.Link(id, r.PostFormValue("legacy"))
		}
		if err != nil {
			s.problem(w, r, who, err)
			return
		}
		done := map[string]string{"approve": "approved", "reject": "rejected", "revoke": "revoked", "renew": "renewed", "link": "linked"}[action]
		s.Log("%s %s an account", who.Email, done)
		http.Redirect(w, r, "/?done="+done, http.StatusSeeOther)
	}
}

func (s *Server) problem(w http.ResponseWriter, r *http.Request, who sealed, err error) {
	status, message := http.StatusBadGateway, "AdGuard did not take the change, so nothing changed. Try again in a moment."
	switch {
	case errors.Is(err, enroll.ErrNotFound):
		status, message = http.StatusNotFound, "There is no such account."
	case errors.Is(err, enroll.ErrState):
		status, message = http.StatusConflict, "The account changed in the meantime, or that does not apply to it. Look at it again."
	default:
		s.Log("%s %s for %s: %v", r.Method, r.URL.Path, who.Email, err)
	}
	data, readErr := s.homePage(r, who)
	if readErr != nil {
		s.fail(w, readErr)
		return
	}
	data.Notice, data.Problem = "", message
	s.render(w, status, data)
}

const cardValueLimit = 70

type card struct {
	Title   string      `json:"title"`
	Message string      `json:"message,omitempty"`
	Fields  []cardField `json:"fields,omitempty"`
	Action  *cardAction `json:"action,omitempty"`
}

type cardField struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Copy  bool   `json:"copy"`
}

type cardAction struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

func (s *Server) cardFor(account store.Account, found addresses) card {
	switch account.Status {
	case store.Approved:
		fields := []cardField{{Label: "Client ID", Value: account.ClientIDs[0], Copy: true}}
		if address := found.DoH; address != "" && utf8.RuneCountInString(address) <= cardValueLimit {
			fields = append([]cardField{{Label: "DNS address", Value: address, Copy: true}}, fields...)
		}
		message := "Use it as the DNS-over-HTTPS address on your devices."
		if found.Problem != "" {
			message = found.Problem
		}
		return card{
			Title:   "Your DNS address",
			Message: message,
			Fields:  fields,
			Action:  &cardAction{Label: "Detail", Href: s.Origin + "/"},
		}
	case store.Denied:
		return card{Title: "No access", Message: "The admin has not given you access. Ask them if this is a mistake."}
	}
	return card{Title: "Waiting for approval", Message: "Thanks. Your request is with the admin; your DNS address shows here once it is approved."}
}

func (s *Server) card(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	token, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || token == "" {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token"}`))
		return
	}
	person, err := s.Pawl.Card(r.Context(), token)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_token"}`))
		return
	}
	account, err := s.Service.Seen(r.Context(), enroll.Person{Sub: person.Sub, Email: person.Email, Name: person.Name})
	if err != nil {
		s.Log("card for %s: %v", person.Email, err)
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"error":"unavailable"}`))
		return
	}
	json.NewEncoder(w).Encode(s.cardFor(account, s.addressesFor(r.Context(), account)))
}
