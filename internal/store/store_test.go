package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAMissingFileIsAnEmptyState(t *testing.T) {
	saved, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	state, err := saved.Read()
	if err != nil || len(state.Accounts) != 0 || len(state.Retired) != 0 || len(state.Made) != 0 {
		t.Fatalf("state %#v err %v", state, err)
	}
}

func TestAnUpdateIsKeptAndSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	saved, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	err = saved.Update(func(state *State) error {
		state.Accounts = append(state.Accounts, Account{ID: "a1", Sub: "pairwise", Email: "budi@example.com", Status: Approved, ClientIDs: []string{"0123456789abcdef0123456789abcdef"}, Requested: at})
		state.Retired = append(state.Retired, "fedcba9876543210fedcba9876543210")
		state.Made = append(state.Made, "budi@example.com · a1")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := again.Read()
	if err != nil || len(state.Accounts) != 1 || state.Accounts[0].Sub != "pairwise" || !state.Accounts[0].Requested.Equal(at) || len(state.Retired) != 1 || len(state.Made) != 1 {
		t.Fatalf("state %#v err %v", state, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestTheDevicesOfAnOlderVersionAreStillRead(t *testing.T) {
	dir := t.TempDir()
	old := `{"devices":[{"id":"d1","owner":"owner@example.com","name":"Phone","status":"approved","clientId":"0123456789abcdef0123456789abcdef","created":"2026-10-12T09:00:00Z"}],"retired":[]}`
	if err := os.WriteFile(filepath.Join(dir, File), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err := saved.Read()
	if err != nil || len(state.Devices) != 1 || state.Devices[0].ClientID != "0123456789abcdef0123456789abcdef" || len(state.Accounts) != 0 {
		t.Fatalf("state %#v err %v", state, err)
	}
}

func TestAFailedUpdateChangesNothing(t *testing.T) {
	saved, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused")
	err = saved.Update(func(state *State) error {
		state.Accounts = append(state.Accounts, Account{ID: "a1"})
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err %v", err)
	}
	if state, _ := saved.Read(); len(state.Accounts) != 0 {
		t.Fatalf("state %#v", state)
	}
}

func TestAnUnreadableFileIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, File)
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saved.Read(); err == nil {
		t.Fatal("a torn file is an error")
	}
	if err := saved.Update(func(*State) error { return nil }); err == nil {
		t.Fatal("an update must not replace a file it cannot read")
	}
	if body, _ := os.ReadFile(path); string(body) != "{" {
		t.Fatalf("the file changed: %q", body)
	}
}
