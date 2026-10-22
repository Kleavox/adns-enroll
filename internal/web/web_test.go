package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/pawl"
	"github.com/Kleavox/adns-enroll/internal/store"
)

const origin = "https://enroll.example.test"

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

type settings struct {
	encryption adguard.Encryption
	logged     bool
	err        error
	logErr     error
}

func (s *settings) Encryption(context.Context) (adguard.Encryption, error) {
	return s.encryption, s.err
}

func (s *settings) QueryLog(context.Context) (bool, error) { return s.logged, s.logErr }

type fakePawl struct {
	people    map[string]pawl.Person
	exchanged []string
}

func (f *fakePawl) AuthorizeURL(_ context.Context, state, nonce, challenge string) (string, error) {
	return "https://paw.example.test/oauth/authorize?" + url.Values{"state": {state}, "nonce": {nonce}, "code_challenge": {challenge}}.Encode(), nil
}

func (f *fakePawl) Exchange(_ context.Context, code, verifier, nonce string) (pawl.Person, error) {
	f.exchanged = append(f.exchanged, code+" "+pawl.Challenge(verifier)+" "+nonce)
	person, found := f.people[code]
	if !found {
		return pawl.Person{}, pawl.ErrDenied
	}
	return person, nil
}

func (f *fakePawl) Card(_ context.Context, token string) (pawl.Person, error) {
	person, found := f.people["card:"+token]
	if !found {
		return pawl.Person{}, pawl.ErrDenied
	}
	return person, nil
}

var (
	owner = pawl.Person{Sub: "pairwise-owner", Email: "owner@example.com", Name: "owner"}
	budi  = pawl.Person{Sub: "pairwise-budi", Email: "budi@example.com", Name: "budi"}
)

type app struct {
	handler http.Handler
	service *enroll.Service
	dns     *quiet
	adguard *settings
	pawl    *fakePawl
}

func newApp(t *testing.T, admins ...string) app {
	t.Helper()
	saved, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dns := &quiet{clients: map[string][]string{}}
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	service := &enroll.Service{Store: saved, DNS: dns, Now: func() time.Time { return now }}
	fake := &fakePawl{people: map[string]pawl.Person{
		"owner-code": owner, "budi-code": budi,
		"card:owner-card": owner, "card:budi-card": budi,
	}}
	read := &settings{
		encryption: adguard.Encryption{Enabled: true, ServerName: "dns.example.test", PortHTTPS: 443, PortDoT: 853, DNSNames: []string{"dns.example.test"}},
		logged:     true,
	}
	server := &Server{
		Service: service,
		AdGuard: read,
		Pawl:    fake,
		Admins:  admins,
		Origin:  origin,
		Key:     []byte("a session key for the tests only"),
		Log:     func(string, ...any) {},
		Now:     func() time.Time { return now },
	}
	return app{handler: server.Handler(), service: service, dns: dns, adguard: read, pawl: fake}
}

func approved(t *testing.T, a app, person pawl.Person) (*http.Cookie, string) {
	t.Helper()
	session := signIn(t, a, strings.TrimPrefix(person.Sub, "pairwise-")+"-code")
	if err := a.service.Approve(context.Background(), account(t, a, person.Sub).ID); err != nil {
		t.Fatal(err)
	}
	return session, account(t, a, person.Sub).ClientIDs[0]
}

func (a app) do(r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	a.handler.ServeHTTP(w, r)
	return w
}

func (a app) get(path string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, origin+path, nil)
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return a.do(r)
}

func (a app) post(path, from string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, origin+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if from != "" {
		r.Header.Set("Origin", from)
	}
	for _, cookie := range cookies {
		r.AddCookie(cookie)
	}
	return a.do(r)
}

func cookie(t *testing.T, w *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s cookie in %v", name, w.Header().Values("Set-Cookie"))
	return nil
}

func signIn(t *testing.T, a app, code string) *http.Cookie {
	t.Helper()
	started := a.get("/auth/signin")
	if started.Code != http.StatusFound {
		t.Fatalf("sign-in answered %d", started.Code)
	}
	target, _ := url.Parse(started.Header().Get("Location"))
	signin := cookie(t, started, "__Host-adns-signin")
	back := a.get("/auth/callback?"+url.Values{"code": {code}, "state": {target.Query().Get("state")}}.Encode(), signin)
	if back.Code != http.StatusSeeOther || back.Header().Get("Location") != "/" {
		t.Fatalf("callback answered %d: %s", back.Code, back.Body.String())
	}
	return cookie(t, back, "__Host-adns")
}

func text(w *httptest.ResponseRecorder) string {
	raw, _ := io.ReadAll(w.Body)
	return string(raw)
}

func account(t *testing.T, a app, sub string) store.Account {
	t.Helper()
	state, err := a.service.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, each := range state.Accounts {
		if each.Sub == sub {
			return each
		}
	}
	t.Fatalf("no account for %s", sub)
	return store.Account{}
}

func TestASignedOutVisitIsSentToPawl(t *testing.T) {
	a := newApp(t)
	w := a.get("/")
	if w.Code != http.StatusFound || w.Header().Get("Location") != "/auth/signin" {
		t.Fatalf("answered %d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestSignInUsesPKCEStateAndNonceKeptInAHostCookie(t *testing.T) {
	a := newApp(t)
	w := a.get("/auth/signin")
	target, _ := url.Parse(w.Header().Get("Location"))
	if target.Host != "paw.example.test" || target.Query().Get("state") == "" || target.Query().Get("nonce") == "" || len(target.Query().Get("code_challenge")) != 43 {
		t.Fatalf("location %s", target)
	}
	c := cookie(t, w, "__Host-adns-signin")
	if !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.Domain != "" {
		t.Fatalf("cookie %#v", c)
	}
	session := signIn(t, a, "budi-code")
	if !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteLaxMode {
		t.Fatalf("session %#v", session)
	}
	exchanged := strings.Fields(a.pawl.exchanged[len(a.pawl.exchanged)-1])
	if exchanged[0] != "budi-code" || len(exchanged) != 3 {
		t.Fatalf("exchanged %v", a.pawl.exchanged)
	}
	if got := account(t, a, budi.Sub); got.Status != store.Waiting || got.Email != budi.Email {
		t.Fatalf("account %#v", got)
	}
}

func TestACallbackThatIsNotThisBrowsersSignInIsRefused(t *testing.T) {
	a := newApp(t)
	started := a.get("/auth/signin")
	target, _ := url.Parse(started.Header().Get("Location"))
	signin := cookie(t, started, "__Host-adns-signin")
	state := target.Query().Get("state")
	tampered := *signin
	tampered.Value = strings.Replace(signin.Value, ".", ".x", 1)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"another state":  a.get("/auth/callback?code=budi-code&state=other", signin),
		"no cookie":      a.get("/auth/callback?code=budi-code&state=" + state),
		"a forged one":   a.get("/auth/callback?code=budi-code&state="+state, &tampered),
		"a refused code": a.get("/auth/callback?code=nobody&state="+state, signin),
	} {
		if w.Code == http.StatusSeeOther {
			t.Errorf("%s signed someone in", name)
		}
		for _, c := range w.Result().Cookies() {
			if c.Name == "__Host-adns" && c.Value != "" {
				t.Errorf("%s set a session", name)
			}
		}
	}
	if cancelled := a.get("/auth/callback?error=access_denied&state="+state, signin); !strings.Contains(text(cancelled), "Sign in again") {
		t.Fatal("a cancelled sign-in does not offer another go")
	}
}

func TestAForgedSessionIsNoSession(t *testing.T) {
	a := newApp(t)
	session := signIn(t, a, "budi-code")
	forged := *session
	forged.Value = "x" + session.Value
	if w := a.get("/", &forged); w.Code != http.StatusFound {
		t.Fatalf("a forged session answered %d", w.Code)
	}
}

func TestAPersonSeesTheirOwnStateAndNeverAnyoneElses(t *testing.T) {
	a := newApp(t, owner.Sub)
	session := signIn(t, a, "budi-code")
	if page := text(a.get("/", session)); !strings.Contains(page, "Waiting for approval") {
		t.Fatalf("page %s", page)
	}
	if err := a.service.Approve(context.Background(), account(t, a, budi.Sub).ID); err != nil {
		t.Fatal(err)
	}
	approved := account(t, a, budi.Sub)
	page := text(a.get("/", session))
	if !strings.Contains(page, "https://dns.example.test/dns-query/"+approved.ClientIDs[0]) || !strings.Contains(page, "Ask the admin") {
		t.Fatalf("page %s", page)
	}
	if strings.Contains(page, "Requests") {
		t.Fatal("a person sees the admin's requests")
	}
	if w := a.post("/admin/accounts/"+approved.ID+"/revoke", origin, nil, session); w.Code != http.StatusForbidden {
		t.Fatalf("a person revoked an account: %d", w.Code)
	}
}

func TestWithNoAdminYetAPersonIsToldTheirSubject(t *testing.T) {
	a := newApp(t)
	session := signIn(t, a, "owner-code")
	if page := text(a.get("/", session)); !strings.Contains(page, "ADMIN_SUBJECTS") || !strings.Contains(page, owner.Sub) {
		t.Fatalf("page %s", page)
	}
}

func TestTheAdminDecidesOnRequestsFromThisSiteOnly(t *testing.T) {
	a := newApp(t, owner.Sub)
	admin := signIn(t, a, "owner-code")
	signIn(t, a, "budi-code")
	page := text(a.get("/", admin))
	if !strings.Contains(page, "Requests") || !strings.Contains(page, budi.Email) {
		t.Fatalf("page %s", page)
	}
	id := account(t, a, budi.Sub).ID
	if w := a.post("/admin/accounts/"+id+"/approve", "https://evil.test", nil, admin); w.Code != http.StatusForbidden {
		t.Fatalf("a foreign form approved: %d", w.Code)
	}
	if w := a.post("/admin/accounts/"+id+"/approve", origin, nil, admin); w.Code != http.StatusSeeOther {
		t.Fatalf("approve answered %d: %s", w.Code, text(w))
	}
	if account(t, a, budi.Sub).Status != store.Approved {
		t.Fatal("not approved")
	}
	before := account(t, a, budi.Sub).ClientIDs[0]
	if w := a.post("/admin/accounts/"+id+"/renew", origin, nil, admin); w.Code != http.StatusSeeOther {
		t.Fatalf("renew answered %d", w.Code)
	}
	if account(t, a, budi.Sub).ClientIDs[0] == before {
		t.Fatal("no new address")
	}
	if w := a.post("/admin/accounts/"+id+"/revoke", origin, nil, admin); w.Code != http.StatusSeeOther {
		t.Fatalf("revoke answered %d", w.Code)
	}
	if account(t, a, budi.Sub).Status != store.Denied {
		t.Fatal("not revoked")
	}
}

func TestTheAdminLinksAPawlAccountToTheAddressesFromBefore(t *testing.T) {
	a := newApp(t, "pairwise-admin")
	err := a.service.Store.Update(func(state *store.State) error {
		state.Accounts = append(state.Accounts, store.Account{ID: "legacy1", Email: budi.Email, Status: store.Approved, ClientIDs: []string{"11111111111111111111111111111111"}, ClientName: "Phone · budi@example.com · d1"})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	a.pawl.people["admin-code"] = pawl.Person{Sub: "pairwise-admin", Email: "admin@example.com"}
	admin := signIn(t, a, "admin-code")
	signIn(t, a, "budi-code")
	page := text(a.get("/", admin))
	if !strings.Contains(page, "Link to the old account") {
		t.Fatalf("page %s", page)
	}
	id := account(t, a, budi.Sub).ID
	if w := a.post("/admin/accounts/"+id+"/link", origin, url.Values{"legacy": {"legacy1"}}, admin); w.Code != http.StatusSeeOther {
		t.Fatalf("link answered %d: %s", w.Code, text(w))
	}
	if got := account(t, a, budi.Sub); got.Status != store.Approved || got.ClientIDs[0] != "11111111111111111111111111111111" {
		t.Fatalf("account %#v", got)
	}
}

type answer struct {
	Title   string `json:"title"`
	Message string `json:"message"`
	Fields  []struct {
		Label string `json:"label"`
		Value string `json:"value"`
		Copy  bool   `json:"copy"`
	} `json:"fields"`
	Action *struct {
		Label string `json:"label"`
		Href  string `json:"href"`
	} `json:"action"`
}

func (a app) card(t *testing.T, token string) (int, answer) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, origin+"/.well-known/pawl/card", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := a.do(r)
	var card answer
	json.NewDecoder(w.Body).Decode(&card)
	if w.Code == http.StatusOK && w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache %q", w.Header().Get("Cache-Control"))
	}
	return w.Code, card
}

func withinPawlsLimits(t *testing.T, card answer) {
	t.Helper()
	length := func(value string) int { return len([]rune(value)) }
	if length(card.Title) < 1 || length(card.Title) > 40 || length(card.Message) > 90 || len(card.Fields) > 2 {
		t.Fatalf("card %#v", card)
	}
	for _, field := range card.Fields {
		if length(field.Label) > 20 || length(field.Value) > 70 {
			t.Fatalf("field %#v", field)
		}
	}
	if card.Action != nil && (length(card.Action.Label) > 16 || !strings.HasPrefix(card.Action.Href, origin+"/")) {
		t.Fatalf("action %#v", card.Action)
	}
}

func TestTheCardThanksANewcomerAndHoldsThemUntilApproved(t *testing.T) {
	a := newApp(t, owner.Sub)
	if status, _ := a.card(t, ""); status != http.StatusUnauthorized {
		t.Fatalf("no token answered %d", status)
	}
	if status, _ := a.card(t, "forged"); status != http.StatusUnauthorized {
		t.Fatalf("a forged token answered %d", status)
	}
	status, card := a.card(t, "budi-card")
	if status != http.StatusOK || card.Title != "Waiting for approval" || !strings.Contains(card.Message, "Thanks") || len(card.Fields) != 0 {
		t.Fatalf("card %d %#v", status, card)
	}
	withinPawlsLimits(t, card)
	if account(t, a, budi.Sub).Status != store.Waiting {
		t.Fatal("the newcomer was not recorded")
	}
	if err := a.service.Approve(context.Background(), account(t, a, budi.Sub).ID); err != nil {
		t.Fatal(err)
	}
	approved := account(t, a, budi.Sub)
	_, card = a.card(t, "budi-card")
	withinPawlsLimits(t, card)
	if card.Title != "Your DNS address" || len(card.Fields) != 2 ||
		card.Fields[0].Value != "https://dns.example.test/dns-query/"+approved.ClientIDs[0] || card.Fields[1].Value != approved.ClientIDs[0] ||
		!card.Fields[0].Copy || card.Action == nil || card.Action.Label != "Detail" || card.Action.Href != origin+"/" {
		t.Fatalf("card %#v", card)
	}
	if err := a.service.Revoke(context.Background(), approved.ID); err != nil {
		t.Fatal(err)
	}
	_, card = a.card(t, "budi-card")
	withinPawlsLimits(t, card)
	if card.Title != "No access" || len(card.Fields) != 0 {
		t.Fatalf("card %#v", card)
	}
}

func TestTheAddressFollowsAdGuardsServerName(t *testing.T) {
	a := newApp(t, owner.Sub)
	session, id := approved(t, a, budi)
	a.adguard.encryption.ServerName = "doh.example.test"
	page := text(a.get("/", session))
	if !strings.Contains(page, "https://doh.example.test/dns-query/"+id) || strings.Contains(page, "dns.example.test") {
		t.Fatalf("page %s", page)
	}
	_, card := a.card(t, "budi-card")
	if len(card.Fields) != 2 || card.Fields[0].Value != "https://doh.example.test/dns-query/"+id {
		t.Fatalf("card %#v", card)
	}
}

func TestWithoutAnAddressFromAdGuardNoneIsGuessed(t *testing.T) {
	a := newApp(t, owner.Sub)
	session, id := approved(t, a, budi)
	for _, broken := range []struct {
		name  string
		cause func()
		says  string
	}{
		{"AdGuard is silent", func() { a.adguard.err = errors.New("adguard tls/status answered 502") }, "AdGuard is not answering"},
		{"encryption is off", func() { a.adguard.err, a.adguard.encryption.Enabled = nil, false }, "AdGuard has no encrypted DNS turned on"},
	} {
		broken.cause()
		page := text(a.get("/", session))
		if strings.Contains(page, "dns-query") || !strings.Contains(page, id) || !strings.Contains(page, broken.says) || strings.Contains(page, "Set it up") {
			t.Errorf("%s: page %s", broken.name, page)
		}
		status, card := a.card(t, "budi-card")
		withinPawlsLimits(t, card)
		if status != http.StatusOK || len(card.Fields) != 1 || card.Fields[0].Value != id || !strings.Contains(card.Message, broken.says) {
			t.Errorf("%s: card %d %#v", broken.name, status, card)
		}
	}
}

func TestAndroidIsOfferedOnlyWhenAdGuardServesIt(t *testing.T) {
	a := newApp(t, owner.Sub)
	session, id := approved(t, a, budi)
	page := text(a.get("/", session))
	if strings.Contains(page, id+".dns.example.test") || !strings.Contains(page, "does not offer") {
		t.Fatalf("page %s", page)
	}
	a.adguard.encryption.DNSNames = []string{"dns.example.test", "*.dns.example.test"}
	page = text(a.get("/", session))
	if !strings.Contains(page, id+".dns.example.test") || strings.Contains(page, "does not offer") {
		t.Fatalf("page %s", page)
	}
}

func TestTheLookupNoteFollowsTheQueryLog(t *testing.T) {
	a := newApp(t, owner.Sub)
	session, _ := approved(t, a, budi)
	const note = "can see the names your devices look up"
	if page := text(a.get("/", session)); !strings.Contains(page, note) {
		t.Fatalf("logged, page %s", page)
	}
	a.adguard.logged = false
	if page := text(a.get("/", session)); strings.Contains(page, note) {
		t.Fatalf("not logged, page %s", page)
	}
	a.adguard.logErr = errors.New("adguard querylog/config answered 502")
	if page := text(a.get("/", session)); !strings.Contains(page, note) {
		t.Fatalf("unknown, page %s", page)
	}
}

func TestAnAddressTooLongForTheCardIsLeftToDetail(t *testing.T) {
	server := &Server{Origin: origin}
	account := store.Account{Status: store.Approved, ClientIDs: []string{"0123456789abcdef0123456789abcdef"}}
	raw, _ := json.Marshal(server.cardFor(account, addresses{DoH: "https://resolver.a-rather-long-private-dns-name.example.test/dns-query/0123456789abcdef0123456789abcdef"}))
	var card answer
	if err := json.Unmarshal(raw, &card); err != nil {
		t.Fatal(err)
	}
	withinPawlsLimits(t, card)
	if len(card.Fields) != 1 || card.Fields[0].Label != "Client ID" || card.Action == nil {
		t.Fatalf("card %#v", card)
	}
}

func TestNothingAnswersBeforeSignInIsSetUp(t *testing.T) {
	saved, _ := store.Open(t.TempDir())
	server := &Server{Service: &enroll.Service{Store: saved, DNS: &quiet{clients: map[string][]string{}}, Now: time.Now}, Missing: "PAWL_CLIENT_SECRET", Log: func(string, ...any) {}, Now: time.Now}
	handler := server.Handler()
	for _, path := range []string{"/", "/auth/signin", "/.well-known/pawl/card"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, origin+path, nil))
		if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "PAWL_CLIENT_SECRET") {
			t.Fatalf("%s answered %d %s", path, w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, origin+"/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("health answered %d", w.Code)
	}
}

func TestSigningOutEndsTheSessionHere(t *testing.T) {
	a := newApp(t)
	session := signIn(t, a, "budi-code")
	if w := a.post("/auth/signout", "https://evil.test", nil, session); w.Code != http.StatusForbidden {
		t.Fatalf("a foreign form signed out: %d", w.Code)
	}
	w := a.post("/auth/signout", origin, nil, session)
	cleared := cookie(t, w, "__Host-adns")
	if cleared.MaxAge >= 0 && cleared.Value != "" {
		t.Fatalf("cookie %#v", cleared)
	}
}
