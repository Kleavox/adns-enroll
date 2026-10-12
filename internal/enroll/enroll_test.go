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

func newService(t *testing.T) (*Service, *memory) {
	t.Helper()
	saved, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dns := newMemory()
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	return &Service{Store: saved, DNS: dns, Now: func() time.Time { return now }}, dns
}

var clientID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func requested(t *testing.T, service *Service, owner, name string) store.Device {
	t.Helper()
	device, err := service.Request(owner, name)
	if err != nil {
		t.Fatal(err)
	}
	return device
}

func approved(t *testing.T, service *Service) store.Device {
	t.Helper()
	device := requested(t, service, "Owner@Example.com", "Phone")
	if err := service.Approve(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	return find(t, service, device.ID)
}

func find(t *testing.T, service *Service, id string) store.Device {
	t.Helper()
	state, err := service.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, device := range state.Devices {
		if device.ID == id {
			return device
		}
	}
	return store.Device{}
}

func TestARequestWaitsWithACleanName(t *testing.T) {
	service, _ := newService(t)
	device := requested(t, service, " Owner@Example.com ", "  Phone  ")
	if device.Owner != "owner@example.com" || device.Name != "Phone" || device.Status != store.Waiting || device.ClientID != "" || len(device.ID) != 16 {
		t.Fatalf("device %#v", device)
	}
	for _, name := range []string{"", "   ", strings.Repeat("x", 41), "Phone\nTwo"} {
		if _, err := service.Request("owner@example.com", name); err == nil {
			t.Fatalf("%q was taken", name)
		}
	}
	if _, err := service.Request("", "Phone"); err == nil {
		t.Fatal("a request needs an owner")
	}
}

func TestApprovingAddsTheClientThenAllowsIt(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	if device.Status != store.Approved || !clientID.MatchString(device.ClientID) || device.Decided.IsZero() {
		t.Fatalf("device %#v", device)
	}
	name := ClientName(device)
	if ids := dns.clients[name]; !slices.Equal(ids, []string{device.ClientID}) {
		t.Fatalf("clients %#v", dns.clients)
	}
	if !slices.Contains(dns.allowed, device.ClientID) || !slices.Contains(dns.allowed, "100.64.0.0/10") || !slices.Contains(dns.allowed, "manual0123") {
		t.Fatalf("allowed %v", dns.allowed)
	}
	if add, allow := slices.Index(dns.calls, "add"), slices.Index(dns.calls, "allow"); add < 0 || allow < add {
		t.Fatalf("calls %v", dns.calls)
	}
	if err := service.Approve(context.Background(), device.ID); err == nil {
		t.Fatal("only a waiting device is approved")
	}
}

func TestAFailedApprovalLeavesNothingBehind(t *testing.T) {
	service, dns := newService(t)
	device := requested(t, service, "owner@example.com", "Phone")
	dns.fail["allow"] = true
	if err := service.Approve(context.Background(), device.ID); err == nil {
		t.Fatal("the failure is reported")
	}
	if len(dns.clients) != 1 || find(t, service, device.ID).Status != store.Waiting {
		t.Fatalf("clients %#v device %#v", dns.clients, find(t, service, device.ID))
	}
	dns.fail = map[string]bool{"add": true}
	if err := service.Approve(context.Background(), device.ID); err == nil || len(dns.allowed) != 2 {
		t.Fatalf("err %v allowed %v", err, dns.allowed)
	}
}

func TestAClientLeftFromAnEarlierTryIsReused(t *testing.T) {
	service, dns := newService(t)
	device := requested(t, service, "owner@example.com", "Phone")
	dns.clients[ClientName(device)] = []string{"leftover"}
	if err := service.Approve(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	got := find(t, service, device.ID)
	if !slices.Equal(dns.clients[ClientName(device)], []string{got.ClientID}) || !slices.Contains(dns.allowed, got.ClientID) {
		t.Fatalf("allowed %v clients %#v", dns.allowed, dns.clients)
	}
}

func TestRejectingKeepsTheRequestAsRejected(t *testing.T) {
	service, dns := newService(t)
	device := requested(t, service, "owner@example.com", "Phone")
	if err := service.Reject(device.ID); err != nil {
		t.Fatal(err)
	}
	if got := find(t, service, device.ID); got.Status != store.Rejected || got.Decided.IsZero() {
		t.Fatalf("device %#v", got)
	}
	if len(dns.calls) != 0 {
		t.Fatalf("rejecting never touches AdGuard: %v", dns.calls)
	}
}

func TestRevokingStopsTheIDBeforeDeletingTheClient(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	dns.calls = nil
	if err := service.Revoke(context.Background(), device.ID); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(dns.allowed, device.ClientID) || dns.clients[ClientName(device)] != nil {
		t.Fatalf("allowed %v clients %#v", dns.allowed, dns.clients)
	}
	if disallow, remove := slices.Index(dns.calls, "disallow"), slices.Index(dns.calls, "delete"); disallow < 0 || remove < disallow {
		t.Fatalf("calls %v", dns.calls)
	}
	state, _ := service.Store.Read()
	if len(state.Devices) != 0 || !slices.Contains(state.Retired, device.ClientID) {
		t.Fatalf("state %#v", state)
	}
	if !slices.Contains(dns.allowed, "manual0123") || dns.clients["Laptop by hand"] == nil {
		t.Fatal("what the app did not make stays")
	}
}

func TestARevokeThatCannotStopTheIDChangesNothing(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	dns.fail["disallow"] = true
	if err := service.Revoke(context.Background(), device.ID); err == nil {
		t.Fatal("the failure is reported")
	}
	if find(t, service, device.ID).Status != store.Approved {
		t.Fatal("the device must stay until its ID is stopped")
	}
}

func TestOwnersRemoveOnlyTheirOwnDevices(t *testing.T) {
	service, _ := newService(t)
	device := approved(t, service)
	if err := service.Remove(context.Background(), "someone@example.com", device.ID); err == nil {
		t.Fatal("another person's device")
	}
	if err := service.Remove(context.Background(), "OWNER@example.com", device.ID); err != nil {
		t.Fatal(err)
	}
	waiting := requested(t, service, "owner@example.com", "Tablet")
	if err := service.Remove(context.Background(), "owner@example.com", waiting.ID); err != nil {
		t.Fatal(err)
	}
	if state, _ := service.Store.Read(); len(state.Devices) != 0 {
		t.Fatalf("state %#v", state)
	}
}

func TestANewAddressNeverLeavesTheDeviceWithoutAWorkingID(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	old := device.ClientID
	dns.calls = nil
	if err := service.Renew(context.Background(), "owner@example.com", device.ID); err != nil {
		t.Fatal(err)
	}
	renewed := find(t, service, device.ID)
	if renewed.ClientID == old || !clientID.MatchString(renewed.ClientID) {
		t.Fatalf("device %#v", renewed)
	}
	if slices.Contains(dns.allowed, old) || !slices.Contains(dns.allowed, renewed.ClientID) || !slices.Equal(dns.clients[ClientName(renewed)], []string{renewed.ClientID}) {
		t.Fatalf("allowed %v clients %#v", dns.allowed, dns.clients)
	}
	if allow, disallow := slices.Index(dns.calls, "allow"), slices.Index(dns.calls, "disallow"); allow < 0 || disallow < allow {
		t.Fatalf("the new ID works before the old one stops: %v", dns.calls)
	}
	if state, _ := service.Store.Read(); !slices.Contains(state.Retired, old) {
		t.Fatalf("state %#v", state)
	}
	if err := service.Renew(context.Background(), "someone@example.com", device.ID); err == nil {
		t.Fatal("another person's device")
	}
}

func TestANewAddressThatCannotBeAllowedKeepsTheOldOne(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	dns.fail["allow"] = true
	if err := service.Renew(context.Background(), "owner@example.com", device.ID); err == nil {
		t.Fatal("the failure is reported")
	}
	if find(t, service, device.ID).ClientID != device.ClientID || !slices.Equal(dns.clients[ClientName(device)], []string{device.ClientID}) || !slices.Contains(dns.allowed, device.ClientID) {
		t.Fatalf("allowed %v clients %#v", dns.allowed, dns.clients)
	}
}

func TestReconcileRepairsDriftBothWays(t *testing.T) {
	service, dns := newService(t)
	device := approved(t, service)
	gone := approved(t, service)
	if err := service.Revoke(context.Background(), gone.ID); err != nil {
		t.Fatal(err)
	}
	delete(dns.clients, ClientName(device))
	dns.allowed = slices.DeleteFunc(dns.allowed, func(id string) bool { return id == device.ClientID })
	dns.allowed = append(dns.allowed, gone.ClientID)
	dns.clients["Stale · owner@example.com · ffff"] = []string{gone.ClientID}
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dns.clients[ClientName(device)], []string{device.ClientID}) || !slices.Contains(dns.allowed, device.ClientID) {
		t.Fatalf("the approved device is back: allowed %v clients %#v", dns.allowed, dns.clients)
	}
	if slices.Contains(dns.allowed, gone.ClientID) || dns.clients["Stale · owner@example.com · ffff"] != nil {
		t.Fatalf("the retired ID is gone: allowed %v clients %#v", dns.allowed, dns.clients)
	}
	if !slices.Contains(dns.allowed, "manual0123") || dns.clients["Laptop by hand"] == nil || !slices.Contains(dns.allowed, "100.64.0.0/10") {
		t.Fatal("what the app did not make stays")
	}
	dns.calls = nil
	if err := service.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, call := range dns.calls {
		if call != "clients" && call != "allowed" {
			t.Fatalf("a settled state changes nothing: %v", dns.calls)
		}
	}
}
