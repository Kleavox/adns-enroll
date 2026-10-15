package main

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/enroll"
	"github.com/Kleavox/adns-enroll/internal/store"
)

func TestAFailedReconcileIsTriedAgainSoon(t *testing.T) {
	if wait := pause(errors.New("adguard clients: timeout")); wait != 30*time.Second {
		t.Fatalf("after a failure: %v", wait)
	}
	if wait := pause(nil); wait != 10*time.Minute {
		t.Fatalf("after a success: %v", wait)
	}
}

type quiet struct{ allowed []string }

func (q *quiet) Clients(context.Context) ([]adguard.Entry, error) { return nil, nil }
func (q *quiet) Add(context.Context, string, string) error        { return nil }
func (q *quiet) SetIDs(context.Context, string, []string) error   { return nil }
func (q *quiet) Delete(context.Context, string) error             { return nil }
func (q *quiet) Allowed(context.Context) ([]string, error)        { return q.allowed, nil }
func (q *quiet) Allow(_ context.Context, id string) error {
	q.allowed = append(q.allowed, id)
	return nil
}
func (q *quiet) Disallow(_ context.Context, ids ...string) error {
	q.allowed = slices.DeleteFunc(q.allowed, func(id string) bool { return slices.Contains(ids, id) })
	return nil
}

func approvedPair(t *testing.T) *enroll.Service {
	t.Helper()
	saved, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service := &enroll.Service{Store: saved, DNS: &quiet{}, Now: time.Now}
	for _, sub := range []string{"stays", "gone"} {
		account, err := service.Seen(context.Background(), enroll.Person{Sub: sub, Email: sub + "@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		if err := service.Approve(context.Background(), account.ID); err != nil {
			t.Fatal(err)
		}
	}
	return service
}

func statuses(t *testing.T, service *enroll.Service) map[string]store.Status {
	t.Helper()
	state, err := service.Store.Read()
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]store.Status{}
	for _, account := range state.Accounts {
		found[account.Sub] = account.Status
	}
	return found
}

func TestPawlDownEndsNobody(t *testing.T) {
	service := approvedPair(t)
	err := liveRound(context.Background(), service, func(context.Context, []string) ([]string, error) {
		return nil, errors.New("pawl answered 503")
	})
	if err == nil {
		t.Fatal("a failed round reads as fine")
	}
	if got := statuses(t, service); got["stays"] != store.Approved || got["gone"] != store.Approved {
		t.Fatalf("statuses %v", got)
	}
}

func TestAnAccountPawlNoLongerKnowsEnds(t *testing.T) {
	service := approvedPair(t)
	var asked []string
	err := liveRound(context.Background(), service, func(_ context.Context, subjects []string) ([]string, error) {
		asked = append(asked, subjects...)
		return []string{"stays"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(slices.Sorted(slices.Values(asked)), []string{"gone", "stays"}) {
		t.Fatalf("asked %v", asked)
	}
	if got := statuses(t, service); got["stays"] != store.Approved || got["gone"] != store.Ended {
		t.Fatalf("statuses %v", got)
	}
}
