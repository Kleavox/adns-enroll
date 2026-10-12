package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/store"
)

const host = "dns-io.kleavox.xyz"

type signedIn struct{}

func (signedIn) Email(r *http.Request) (string, error) {
	if email := r.Header.Get("X-Test-Email"); email != "" {
		return email, nil
	}
	return "", errors.New("not signed in")
}

type quiet struct {
	clients map[string][]string
	allowed []string
}

func (q *quiet) Clients(context.Context) ([]adguard.Entry, error) {
	var entries []adguard.Entry
	for name, ids := range q.clients {
		entries = append(entries, adguard.Entry{Name: name, IDs: ids})
	}
	return entries, nil
}
func (q *quiet) Add(_ context.Context, name, id string) error {
	q.clients[name] = []string{id}
	return nil
}
func (q *quiet) SetIDs(_ context.Context, name string, ids []string) error {
	q.clients[name] = ids
	return nil
}
func (q *quiet) Delete(_ context.Context, name string) error {
	delete(q.clients, name)
	return nil
}
func (q *quiet) Allowed(context.Context) ([]string, error) { return q.allowed, nil }
func (q *quiet) Allow(_ context.Context, id string) error {
	q.allowed = append(q.allowed, id)
	return nil
}
func (q *quiet) Disallow(_ context.Context, ids ...string) error {
	q.allowed = slices.DeleteFunc(q.allowed, func(item string) bool { return slices.Contains(ids, item) })
	return nil
}

type app struct {
	handler http.Handler
	service *enroll.Service
	dns     *quiet
}

func newApp(t *testing.T) app {
	t.Helper()
	saved, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dns := &quiet{clients: map[string][]string{}}
	service := &enroll.Service{Store: saved, DNS: dns, Now: func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) }}
	server := &Server{Service: service, Identity: signedIn{}, Admins: []string{"admin@example.com"}, DoHHost: "dns.kleavox.xyz", Log: func(string, ...any) {}}
	return app{handler: server.Handler(), service: service, dns: dns}
}

func (a app) get(path, email string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "https://"+host+path, nil)
	if email != "" {
		r.Header.Set("X-Test-Email", email)
	}
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w
}

func (a app) post(path, email, origin string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "https://"+host+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if email != "" {
		r.Header.Set("X-Test-Email", email)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w
}

const self = "https://" + host

func body(w *httptest.ResponseRecorder) string {
	raw, _ := io.ReadAll(w.Body)
	return string(raw)
}

func (a app) only(t *testing.T) store.Device {
	t.Helper()
	state, err := a.service.Store.Read()
	if err != nil || len(state.Devices) != 1 {
		t.Fatalf("state %#v err %v", state, err)
	}
	return state.Devices[0]
}

func TestNobodyGetsInWithoutSigningIn(t *testing.T) {
	a := newApp(t)
	for _, path := range []string{"/", "/admin"} {
		if w := a.get(path, ""); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if w := a.post("/devices", "", self, url.Values{"name": {"Phone"}}); w.Code != http.StatusUnauthorized {
		t.Fatalf("post: %d", w.Code)
	}
	if w := a.get("/healthz", ""); w.Code != http.StatusOK || body(w) != "ok" {
		t.Fatalf("health: %d", w.Code)
	}
}

type unready struct{}

func (unready) Email(*http.Request) (string, error) {
	return "", Unready("Sign-in is not set up yet: ACCESS_AUD is missing.")
}

func TestAnAppWithoutSignInSetUpSaysSo(t *testing.T) {
	a := newApp(t)
	server := &Server{Service: a.service, Identity: unready{}, DoHHost: "dns.kleavox.xyz", Log: func(string, ...any) {}}
	r := httptest.NewRequest(http.MethodGet, "https://"+host+"/", nil)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(body(w), "ACCESS_AUD") {
		t.Fatalf("code %d", w.Code)
	}
}

func TestAPersonRequestsADeviceAndSeesItWait(t *testing.T) {
	a := newApp(t)
	w := a.post("/devices", "budi@example.com", self, url.Values{"name": {"Phone"}})
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		t.Fatalf("code %d location %q", w.Code, w.Header().Get("Location"))
	}
	page := body(a.get("/", "budi@example.com"))
	if !strings.Contains(page, `<span class="name">Phone</span>`) || !strings.Contains(page, "Waiting for approval") {
		t.Fatalf("page %s", page)
	}
	if other := body(a.get("/", "sari@example.com")); strings.Contains(other, `<span class="name">Phone</span>`) {
		t.Fatal("another person sees the device")
	}
}

func TestChangesFromAnotherSiteAreRefused(t *testing.T) {
	a := newApp(t)
	for _, origin := range []string{"", "https://evil.example.com", "null", "https://" + host + ".evil.example.com"} {
		if w := a.post("/devices", "budi@example.com", origin, url.Values{"name": {"Phone"}}); w.Code != http.StatusForbidden {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	if state, _ := a.service.Store.Read(); len(state.Devices) != 0 {
		t.Fatalf("state %#v", state)
	}
}

func (a app) fetched(site, origin, requestHost string) int {
	r := httptest.NewRequest(http.MethodPost, "https://"+requestHost+"/devices", strings.NewReader(url.Values{"name": {"Phone"}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("X-Test-Email", "budi@example.com")
	r.Header.Set("Origin", origin)
	r.Header.Set("Sec-Fetch-Site", site)
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w.Code
}

func TestTheBrowserSaysWhetherAChangeCameFromThisSite(t *testing.T) {
	a := newApp(t)
	if code := a.fetched("same-origin", self, "enroll:8080"); code != http.StatusSeeOther {
		t.Fatalf("a tunnel that rewrites the host still works: %d", code)
	}
	for _, site := range []string{"cross-site", "same-site", "none"} {
		if code := a.fetched(site, self, host); code != http.StatusForbidden {
			t.Fatalf("%s: %d", site, code)
		}
	}
}

func TestOnlyAdminsApprove(t *testing.T) {
	a := newApp(t)
	a.post("/devices", "budi@example.com", self, url.Values{"name": {"Phone"}})
	device := a.only(t)
	if w := a.get("/admin", "budi@example.com"); w.Code != http.StatusForbidden {
		t.Fatalf("admin page: %d", w.Code)
	}
	if w := a.post("/admin/devices/"+device.ID+"/approve", "budi@example.com", self, nil); w.Code != http.StatusForbidden {
		t.Fatalf("approve: %d", w.Code)
	}
	admin := body(a.get("/admin", "ADMIN@example.com"))
	if !strings.Contains(admin, "budi@example.com") || !strings.Contains(admin, `<span class="name">Phone</span>`) {
		t.Fatalf("admin page %s", admin)
	}
	if w := a.post("/admin/devices/"+device.ID+"/approve", "admin@example.com", self, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("approve: %d %s", w.Code, body(w))
	}
	approved := a.only(t)
	page := body(a.get("/", "budi@example.com"))
	if !strings.Contains(page, "https://dns.kleavox.xyz/dns-query/"+approved.ClientID) {
		t.Fatalf("the owner sees the address: %s", page)
	}
	if strings.Contains(body(a.get("/", "sari@example.com")), approved.ClientID) {
		t.Fatal("nobody else sees the address")
	}
}

func TestOwnersRenewAndRemoveOnlyTheirOwn(t *testing.T) {
	a := newApp(t)
	a.post("/devices", "budi@example.com", self, url.Values{"name": {"Phone"}})
	device := a.only(t)
	a.post("/admin/devices/"+device.ID+"/approve", "admin@example.com", self, nil)
	old := a.only(t).ClientID
	if w := a.post("/devices/"+device.ID+"/renew", "sari@example.com", self, nil); w.Code != http.StatusNotFound {
		t.Fatalf("someone else renews: %d", w.Code)
	}
	if w := a.post("/devices/"+device.ID+"/renew", "budi@example.com", self, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("renew: %d %s", w.Code, body(w))
	}
	if a.only(t).ClientID == old {
		t.Fatal("a new address was not made")
	}
	if w := a.post("/devices/"+device.ID+"/remove", "budi@example.com", self, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	if state, _ := a.service.Store.Read(); len(state.Devices) != 0 {
		t.Fatalf("state %#v", state)
	}
}

func TestAProblemIsShownWithoutEchoingInput(t *testing.T) {
	a := newApp(t)
	w := a.post("/devices", "budi@example.com", self, url.Values{"name": {strings.Repeat("x", 41)}})
	if w.Code != http.StatusBadRequest || !strings.Contains(body(w), "at most 40 characters") {
		t.Fatalf("code %d", w.Code)
	}
	a.post("/devices", "budi@example.com", self, url.Values{"name": {`<script>alert(1)</script>`}})
	page := body(a.get("/", "budi@example.com"))
	if strings.Contains(page, "<script>alert") || !strings.Contains(page, "&lt;script&gt;") {
		t.Fatal("a device name is escaped")
	}
}

func TestEveryPageCarriesTheSecurityHeaders(t *testing.T) {
	a := newApp(t)
	w := a.get("/", "budi@example.com")
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "style-src 'self'", "frame-ancestors 'none'", "form-action 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("csp %q is missing %q", csp, want)
		}
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("headers %v", w.Header())
	}
	if regexp.MustCompile(`<script>[^<]`).MatchString(body(w)) {
		t.Fatal("no inline script")
	}
	if script := a.get("/static/app.js", ""); script.Code != http.StatusOK || !strings.Contains(script.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("script %d %q", script.Code, script.Header().Get("Content-Type"))
	}
}
