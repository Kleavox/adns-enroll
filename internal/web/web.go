package web

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/store"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static
var static embed.FS

var pages = template.Must(template.ParseFS(templates, "templates/*.html"))

const policy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

type Identity interface {
	Email(r *http.Request) (string, error)
}

type Server struct {
	Service  *enroll.Service
	Identity Identity
	Admins   []string
	DoHHost  string
	Log      func(format string, args ...any)
}

var notices = map[string]string{
	"requested": "Your request is waiting for approval.",
	"renewed":   "The device has a new address. Put it in place of the old one; the old one has stopped working.",
	"removed":   "The device is removed and its address has stopped working.",
	"approved":  "Approved. The address works now.",
	"rejected":  "Rejected.",
	"revoked":   "Revoked. The address has stopped working.",
}

type view struct {
	ID      string
	Name    string
	Owner   string
	Status  string
	Label   string
	URL     string
	Created time.Time
}

type page struct {
	Email    string
	Admin    bool
	Section  string
	Devices  []view
	Waiting  []view
	Decided  []view
	Notice   string
	Problem  string
	Template string
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(static, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(assets)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /{$}", s.person(s.devices))
	mux.HandleFunc("POST /devices", s.change(s.request))
	mux.HandleFunc("POST /devices/{id}/remove", s.change(s.remove))
	mux.HandleFunc("POST /devices/{id}/renew", s.change(s.renew))
	mux.HandleFunc("GET /admin", s.person(s.admin(s.requests)))
	mux.HandleFunc("POST /admin/devices/{id}/approve", s.change(s.admin(s.approve)))
	mux.HandleFunc("POST /admin/devices/{id}/reject", s.change(s.admin(s.reject)))
	mux.HandleFunc("POST /admin/devices/{id}/revoke", s.change(s.admin(s.revoke)))
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

type Unready string

func (u Unready) Error() string { return string(u) }

type handler func(w http.ResponseWriter, r *http.Request, email string)

func (s *Server) person(next handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		email, err := s.Identity.Email(r)
		var unready Unready
		if errors.As(err, &unready) {
			http.Error(w, unready.Error(), http.StatusServiceUnavailable)
			return
		}
		if err != nil || email == "" {
			http.Error(w, "Sign in first.", http.StatusUnauthorized)
			return
		}
		next(w, r, enroll.Owner(email))
	}
}

func sameOrigin(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	origin, err := url.Parse(r.Header.Get("Origin"))
	return err == nil && origin.Host != "" && origin.Host == r.Host && (origin.Scheme == "https" || origin.Scheme == "http")
}

func (s *Server) change(next handler) http.HandlerFunc {
	return s.person(func(w http.ResponseWriter, r *http.Request, email string) {
		if !sameOrigin(r) {
			http.Error(w, "This change has to come from this site.", http.StatusForbidden)
			return
		}
		next(w, r, email)
	})
}

func (s *Server) isAdmin(email string) bool {
	return slices.ContainsFunc(s.Admins, func(admin string) bool { return enroll.Owner(admin) == email })
}

func (s *Server) admin(next handler) handler {
	return func(w http.ResponseWriter, r *http.Request, email string) {
		if !s.isAdmin(email) {
			http.Error(w, "Only an admin can do this.", http.StatusForbidden)
			return
		}
		next(w, r, email)
	}
}

func (s *Server) address(device store.Device) string {
	if device.Status != store.Approved || device.ClientID == "" {
		return ""
	}
	return "https://" + s.DoHHost + "/dns-query/" + device.ClientID
}

func label(status store.Status) string {
	switch status {
	case store.Waiting:
		return "Waiting for approval"
	case store.Approved:
		return "Active"
	case store.Rejected:
		return "Rejected"
	}
	return string(status)
}

func (s *Server) view(device store.Device, withAddress bool) view {
	shown := view{ID: device.ID, Name: device.Name, Owner: device.Owner, Status: string(device.Status), Label: label(device.Status), Created: device.Created}
	if withAddress {
		shown.URL = s.address(device)
	}
	return shown
}

func (s *Server) render(w http.ResponseWriter, status int, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, "layout", data); err != nil {
		s.Log("render %s: %v", data.Template, err)
	}
}

func (s *Server) devicesPage(email string, r *http.Request) (page, error) {
	state, err := s.Service.Store.Read()
	if err != nil {
		return page{}, err
	}
	data := page{Email: email, Admin: s.isAdmin(email), Section: "devices", Template: "devices", Notice: notices[r.URL.Query().Get("done")]}
	for _, device := range state.Devices {
		if device.Owner == email {
			data.Devices = append(data.Devices, s.view(device, true))
		}
	}
	return data, nil
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request, email string) {
	data, err := s.devicesPage(email, r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, data)
}

func (s *Server) requestsPage(email string, r *http.Request) (page, error) {
	state, err := s.Service.Store.Read()
	if err != nil {
		return page{}, err
	}
	data := page{Email: email, Admin: true, Section: "admin", Template: "admin", Notice: notices[r.URL.Query().Get("done")]}
	for _, device := range state.Devices {
		if device.Status == store.Waiting {
			data.Waiting = append(data.Waiting, s.view(device, false))
		} else {
			data.Decided = append(data.Decided, s.view(device, false))
		}
	}
	return data, nil
}

func (s *Server) requests(w http.ResponseWriter, r *http.Request, email string) {
	data, err := s.requestsPage(email, r)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.render(w, http.StatusOK, data)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.Log("store: %v", err)
	http.Error(w, "The device list could not be read.", http.StatusInternalServerError)
}

func (s *Server) problem(w http.ResponseWriter, r *http.Request, email string, err error, onAdmin bool) {
	status, message := http.StatusBadGateway, "AdGuard did not take the change, so nothing changed. Try again in a moment."
	var invalid enroll.Invalid
	switch {
	case errors.As(err, &invalid):
		status, message = http.StatusBadRequest, invalid.Error()
	case errors.Is(err, enroll.ErrNotFound):
		status, message = http.StatusNotFound, "There is no such device."
	case errors.Is(err, enroll.ErrState):
		status, message = http.StatusConflict, "The device changed in the meantime. Look at it again."
	default:
		s.Log("%s %s for %s: %v", r.Method, r.URL.Path, email, err)
	}
	data, readErr := s.devicesPage(email, r)
	if onAdmin {
		data, readErr = s.requestsPage(email, r)
	}
	if readErr != nil {
		s.fail(w, readErr)
		return
	}
	data.Notice, data.Problem = "", message
	s.render(w, status, data)
}

func done(w http.ResponseWriter, r *http.Request, path, what string) {
	http.Redirect(w, r, path+"?done="+what, http.StatusSeeOther)
}

func (s *Server) request(w http.ResponseWriter, r *http.Request, email string) {
	device, err := s.Service.Request(email, r.PostFormValue("name"))
	if err != nil {
		s.problem(w, r, email, err, false)
		return
	}
	s.Log("%s asked for %s", email, device.Name)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request, email string) {
	if err := s.Service.Remove(r.Context(), email, r.PathValue("id")); err != nil {
		s.problem(w, r, email, err, false)
		return
	}
	s.Log("%s removed a device", email)
	done(w, r, "/", "removed")
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request, email string) {
	if err := s.Service.Renew(r.Context(), email, r.PathValue("id")); err != nil {
		s.problem(w, r, email, err, false)
		return
	}
	s.Log("%s made a new address", email)
	done(w, r, "/", "renewed")
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, email string) {
	if err := s.Service.Approve(r.Context(), r.PathValue("id")); err != nil {
		s.problem(w, r, email, err, true)
		return
	}
	s.Log("%s approved a device", email)
	done(w, r, "/admin", "approved")
}

func (s *Server) reject(w http.ResponseWriter, r *http.Request, email string) {
	if err := s.Service.Reject(r.PathValue("id")); err != nil {
		s.problem(w, r, email, err, true)
		return
	}
	s.Log("%s rejected a device", email)
	done(w, r, "/admin", "rejected")
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, email string) {
	if err := s.Service.Revoke(r.Context(), r.PathValue("id")); err != nil {
		s.problem(w, r, email, err, true)
		return
	}
	s.Log("%s revoked a device", email)
	done(w, r, "/admin", "revoked")
}
