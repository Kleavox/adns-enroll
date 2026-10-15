package enroll

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/store"
)

var boom = errors.New("boom")

type memory struct {
	clients map[string][]string
	allowed []string
	fail    map[string]bool
	calls   []string
}

func newMemory() *memory {
	return &memory{clients: map[string][]string{"Laptop by hand": {"manual0123"}}, allowed: []string{"100.64.0.0/10", "manual0123"}, fail: map[string]bool{}}
}

func (m *memory) step(name string) error {
	m.calls = append(m.calls, name)
	if m.fail[name] {
		return boom
	}
	return nil
}

func (m *memory) owner(id string) string {
	for name, ids := range m.clients {
		if slices.Contains(ids, id) {
			return name
		}
	}
	return ""
}

func (m *memory) Clients(context.Context) ([]adguard.Entry, error) {
	if err := m.step("clients"); err != nil {
		return nil, err
	}
	var entries []adguard.Entry
	for name, ids := range m.clients {
		entries = append(entries, adguard.Entry{Name: name, IDs: slices.Clone(ids)})
	}
	slices.SortFunc(entries, func(a, b adguard.Entry) int { return strings.Compare(a.Name, b.Name) })
	return entries, nil
}

func (m *memory) Add(_ context.Context, name, id string) error {
	if err := m.step("add"); err != nil {
		return err
	}
	if _, taken := m.clients[name]; taken {
		return errors.New("taken")
	}
	if holder := m.owner(id); holder != "" {
		return errors.New("id already belongs to " + holder)
	}
	m.clients[name] = []string{id}
	return nil
}

func (m *memory) SetIDs(_ context.Context, name string, ids []string) error {
	if err := m.step("setids"); err != nil {
		return err
	}
	if _, found := m.clients[name]; !found {
		return errors.New("missing")
	}
	for _, id := range ids {
		if holder := m.owner(id); holder != "" && holder != name {
			return errors.New("id already belongs to " + holder)
		}
	}
	m.clients[name] = slices.Clone(ids)
	return nil
}

func (m *memory) Delete(_ context.Context, name string) error {
	if err := m.step("delete"); err != nil {
		return err
	}
	delete(m.clients, name)
	return nil
}

func (m *memory) Allowed(context.Context) ([]string, error) {
	if err := m.step("allowed"); err != nil {
		return nil, err
	}
	return slices.Clone(m.allowed), nil
}

func (m *memory) Allow(_ context.Context, id string) error {
	if err := m.step("allow"); err != nil {
		return err
	}
	if !slices.Contains(m.allowed, id) {
		m.allowed = append(m.allowed, id)
	}
	return nil
}

func (m *memory) Disallow(_ context.Context, ids ...string) error {
	if err := m.step("disallow"); err != nil {
		return err
	}
	m.allowed = slices.DeleteFunc(m.allowed, func(item string) bool { return slices.Contains(ids, item) })
	return nil
}

var ctx = context.Background()

var clientID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func newService(t *testing.T) (*Service, *memory) {
	t.Helper()
	saved, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dns := newMemory()
	now := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	return &Service{Store: saved, DNS: dns, Now: func() time.Time { return now }}, dns
}

var budi = Person{Sub: "pairwise-budi", Email: "Budi@Example.com", Name: "budi"}

func seen(t *testing.T, service *Service, person Person) store.Account {
	t.Helper()
	account, err := service.Seen(ctx, person)
	if err != nil {
		t.Fatal(err)
	}
	return account
}

func approved(t *testing.T, service *Service, person Person) store.Account {
	t.Helper()
	account := seen(t, service, person)
	if err := service.Approve(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	return find(t, service, account.ID)
}

func find(t *testing.T, service *Service, id string) store.Account {
	t.Helper()
	state, err := service.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range state.Accounts {
		if account.ID == id {
			return account
		}
	}
	t.Fatalf("no account %s", id)
	return store.Account{}
}

func untouched(t *testing.T, dns *memory) {
	t.Helper()
	if ids := dns.clients["Laptop by hand"]; !slices.Equal(ids, []string{"manual0123"}) {
		t.Fatalf("the hand-made client changed: %v", ids)
	}
	for _, kept := range []string{"100.64.0.0/10", "manual0123"} {
		if !slices.Contains(dns.allowed, kept) {
			t.Fatalf("a hand-made entry left Allowed clients: %v", dns.allowed)
		}
	}
}

func TestAFirstVisitRecordsOneWaitingAccountForTheSubject(t *testing.T) {
	service, _ := newService(t)
	first := seen(t, service, budi)
	if first.Status != store.Waiting || first.Sub != budi.Sub || first.Email != "budi@example.com" || first.Name != "budi" {
		t.Fatalf("account %#v", first)
	}
	again := seen(t, service, Person{Sub: budi.Sub, Email: "budi@new.example", Name: "budi"})
	state, _ := service.Store.Read()
	if again.ID != first.ID || len(state.Accounts) != 1 || state.Accounts[0].Email != "budi@new.example" {
		t.Fatalf("accounts %#v", state.Accounts)
	}
	if _, err := service.Seen(ctx, Person{Email: "nobody@example.com"}); err == nil {
		t.Fatal("an account needs a subject")
	}
}

func TestApprovingGivesTheAccountOneAddressInAdGuard(t *testing.T) {
	service, dns := newService(t)
	account := approved(t, service, budi)
	if account.Status != store.Approved || len(account.ClientIDs) != 1 || !clientID.MatchString(account.ClientIDs[0]) {
		t.Fatalf("account %#v", account)
	}
	if ids := dns.clients[account.ClientName]; !slices.Equal(ids, account.ClientIDs) {
		t.Fatalf("client %v", dns.clients)
	}
	if !slices.Contains(dns.allowed, account.ClientIDs[0]) {
		t.Fatalf("allowed %v", dns.allowed)
	}
	state, _ := service.Store.Read()
	if !slices.Contains(state.Made, account.ClientName) {
		t.Fatalf("made %v", state.Made)
	}
	untouched(t, dns)
}

func TestAFailedApprovalLeavesNothingBehind(t *testing.T) {
	service, dns := newService(t)
	account := seen(t, service, budi)
	dns.fail["allow"] = true
	if err := service.Approve(ctx, account.ID); err == nil {
		t.Fatal("expected the approval to fail")
	}
	if got := find(t, service, account.ID); got.Status != store.Waiting || len(got.ClientIDs) != 0 {
		t.Fatalf("account %#v", got)
	}
	if len(dns.clients) != 1 {
		t.Fatalf("clients %v", dns.clients)
	}
	dns.fail["allow"] = false
	if err := service.Approve(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
}

func TestRejectingAndRevokingLeaveNoWorkingAddress(t *testing.T) {
	service, dns := newService(t)
	waiting := seen(t, service, Person{Sub: "s2", Email: "sari@example.com"})
	if err := service.Reject(waiting.ID); err != nil {
		t.Fatal(err)
	}
	if find(t, service, waiting.ID).Status != store.Denied {
		t.Fatal("not denied")
	}
	account := approved(t, service, budi)
	old := account.ClientIDs[0]
	if err := service.Revoke(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	got := find(t, service, account.ID)
	if got.Status != store.Denied || len(got.ClientIDs) != 0 || slices.Contains(dns.allowed, old) || dns.clients[account.ClientName] != nil {
		t.Fatalf("account %#v allowed %v clients %v", got, dns.allowed, dns.clients)
	}
	state, _ := service.Store.Read()
	if !slices.Contains(state.Retired, old) {
		t.Fatalf("retired %v", state.Retired)
	}
	again := approved(t, service, budi)
	if again.ClientIDs[0] == old {
		t.Fatal("an approval after a revoke makes a new address")
	}
	untouched(t, dns)
}

func TestANewAddressNeverLeavesAMomentWithoutOne(t *testing.T) {
	service, dns := newService(t)
	account := approved(t, service, budi)
	old := account.ClientIDs[0]
	if err := service.Renew(ctx, account.ID); err != nil {
		t.Fatal(err)
	}
	got := find(t, service, account.ID)
	fresh := got.ClientIDs[0]
	if fresh == old || len(got.ClientIDs) != 1 || !slices.Equal(dns.clients[got.ClientName], []string{fresh}) {
		t.Fatalf("account %#v clients %v", got, dns.clients)
	}
	if slices.Contains(dns.allowed, old) || !slices.Contains(dns.allowed, fresh) {
		t.Fatalf("allowed %v", dns.allowed)
	}
	firstAllow := slices.Index(dns.calls, "allow")
	firstDisallow := slices.Index(dns.calls[firstAllow:], "disallow")
	if firstDisallow < 0 {
		t.Fatalf("calls %v", dns.calls)
	}
	untouched(t, dns)
}

func TestARenewalThatFailsKeepsTheOldAddress(t *testing.T) {
	service, dns := newService(t)
	account := approved(t, service, budi)
	dns.fail["allow"] = true
	if err := service.Renew(ctx, account.ID); err == nil {
		t.Fatal("expected the renewal to fail")
	}
	got := find(t, service, account.ID)
	if !slices.Equal(got.ClientIDs, account.ClientIDs) || !slices.Equal(dns.clients[got.ClientName], account.ClientIDs) {
		t.Fatalf("account %#v clients %v", got, dns.clients)
	}
}

func legacyState(t *testing.T, service *Service) {
	t.Helper()
	day := func(d int) time.Time { return time.Date(2026, 10, d, 9, 0, 0, 0, time.UTC) }
	err := service.Store.Update(func(state *store.State) error {
		state.Devices = []store.Device{
			{ID: "d1", Owner: "owner@example.com", Name: "Laptop", Status: "approved", ClientID: "11111111111111111111111111111111", Created: day(12)},
			{ID: "d2", Owner: "owner@example.com", Name: "Phone", Status: "approved", ClientID: "22222222222222222222222222222222", Created: day(13)},
			{ID: "d3", Owner: "owner@example.com", Name: "Tablet", Status: "waiting", Created: day(14)},
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDevicesFromBeforeBecomeOneAccountThatKeepsEveryAddress(t *testing.T) {
	service, dns := newService(t)
	legacyState(t, service)
	dns.clients["Laptop · owner@example.com · d1"] = []string{"11111111111111111111111111111111"}
	dns.clients["Phone · owner@example.com · d2"] = []string{"22222222222222222222222222222222"}
	dns.allowed = append(dns.allowed, "11111111111111111111111111111111", "22222222222222222222222222222222")
	if err := service.Migrate(); err != nil {
		t.Fatal(err)
	}
	state, _ := service.Store.Read()
	if len(state.Devices) != 0 || len(state.Accounts) != 1 {
		t.Fatalf("state %#v", state)
	}
	legacy := state.Accounts[0]
	if legacy.Sub != "" || legacy.Status != store.Approved || legacy.Email != "owner@example.com" || legacy.ClientName != "Phone · owner@example.com · d2" || !slices.Equal(legacy.ClientIDs, []string{"22222222222222222222222222222222", "11111111111111111111111111111111"}) {
		t.Fatalf("legacy %#v", legacy)
	}
	if err := service.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if _, left := dns.clients["Laptop · owner@example.com · d1"]; left {
		t.Fatalf("clients %v", dns.clients)
	}
	if !slices.Equal(dns.clients["Phone · owner@example.com · d2"], legacy.ClientIDs) {
		t.Fatalf("clients %v", dns.clients)
	}
	for _, id := range legacy.ClientIDs {
		if !slices.Contains(dns.allowed, id) {
			t.Fatalf("allowed %v", dns.allowed)
		}
	}
	untouched(t, dns)
	if err := service.Migrate(); err != nil {
		t.Fatal(err)
	}
	if again, _ := service.Store.Read(); len(again.Accounts) != 1 {
		t.Fatalf("a second start converted twice: %#v", again.Accounts)
	}
}

func TestLinkingMovesTheOldAddressesToThePawlAccount(t *testing.T) {
	service, dns := newService(t)
	legacyState(t, service)
	if err := service.Migrate(); err != nil {
		t.Fatal(err)
	}
	before, _ := service.Store.Read()
	legacy := before.Accounts[0]
	owner := seen(t, service, Person{Sub: "pairwise-owner", Email: "Owner@example.com"})
	stranger := seen(t, service, Person{Sub: "pairwise-other", Email: "other@example.com"})
	if err := service.Link(stranger.ID, legacy.ID); !errors.Is(err, ErrState) {
		t.Fatalf("a different email links: %v", err)
	}
	if err := service.Link(owner.ID, legacy.ID); err != nil {
		t.Fatal(err)
	}
	after, _ := service.Store.Read()
	if len(after.Accounts) != 2 {
		t.Fatalf("accounts %#v", after.Accounts)
	}
	got := find(t, service, owner.ID)
	if got.Status != store.Approved || got.ClientName != legacy.ClientName || !slices.Equal(got.ClientIDs, legacy.ClientIDs) {
		t.Fatalf("account %#v", got)
	}
	if err := service.Link(owner.ID, legacy.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("linking twice: %v", err)
	}
	untouched(t, dns)
}

func TestAnAccountGoneFromPawlStopsAndComesBackWithTheSameAddress(t *testing.T) {
	service, dns := newService(t)
	gone := approved(t, service, budi)
	stays := approved(t, service, Person{Sub: "pairwise-sari", Email: "sari@example.com"})
	asked, err := service.Subjects()
	if err != nil || !slices.Equal(slices.Sorted(slices.Values(asked)), []string{"pairwise-budi", "pairwise-sari"}) {
		t.Fatalf("subjects %v err %v", asked, err)
	}
	later := approved(t, service, Person{Sub: "pairwise-later", Email: "later@example.com"})
	if err := service.EndMissing(ctx, asked, []string{"pairwise-sari"}); err != nil {
		t.Fatal(err)
	}
	ended := find(t, service, gone.ID)
	if ended.Status != store.Ended || !slices.Equal(ended.ClientIDs, gone.ClientIDs) || slices.Contains(dns.allowed, gone.ClientIDs[0]) || dns.clients[gone.ClientName] != nil {
		t.Fatalf("ended %#v allowed %v", ended, dns.allowed)
	}
	if find(t, service, stays.ID).Status != store.Approved || find(t, service, later.ID).Status != store.Approved {
		t.Fatal("an account Pawl still knows, or one not asked about, was ended")
	}
	back := seen(t, service, budi)
	if back.Status != store.Approved || !slices.Equal(back.ClientIDs, gone.ClientIDs) || !slices.Contains(dns.allowed, gone.ClientIDs[0]) || !slices.Equal(dns.clients[gone.ClientName], gone.ClientIDs) {
		t.Fatalf("back %#v clients %v", back, dns.clients)
	}
	untouched(t, dns)
}

func TestReconcileRepairsDriftBothWaysAndNothingElse(t *testing.T) {
	service, dns := newService(t)
	account := approved(t, service, budi)
	revoked := approved(t, service, Person{Sub: "pairwise-sari", Email: "sari@example.com"})
	if err := service.Revoke(ctx, revoked.ID); err != nil {
		t.Fatal(err)
	}
	delete(dns.clients, account.ClientName)
	dns.allowed = slices.DeleteFunc(dns.allowed, func(id string) bool { return id == account.ClientIDs[0] })
	dns.allowed = append(dns.allowed, revoked.ClientIDs...)
	dns.allowed = append(dns.allowed, find(t, service, revoked.ID).ClientIDs...)
	state, _ := service.Store.Read()
	dns.allowed = append(dns.allowed, state.Retired...)
	if err := service.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dns.clients[account.ClientName], account.ClientIDs) || !slices.Contains(dns.allowed, account.ClientIDs[0]) {
		t.Fatalf("clients %v allowed %v", dns.clients, dns.allowed)
	}
	for _, id := range state.Retired {
		if slices.Contains(dns.allowed, id) {
			t.Fatalf("a retired address still works: %v", dns.allowed)
		}
	}
	untouched(t, dns)
}
