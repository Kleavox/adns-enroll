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
	if err != nil || len(state.Devices) != 0 || len(state.Retired) != 0 {
		t.Fatalf("state %#v err %v", state, err)
	}
}

func TestAnUpdateIsKeptAndSurvivesAReopen(t *testing.T) {
	dir := t.TempDir()
	saved, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	err = saved.Update(func(state *State) error {
		state.Devices = append(state.Devices, Device{ID: "a1", Owner: "owner@example.com", Name: "Phone", Status: Waiting, Created: at})
		state.Retired = append(state.Retired, "0123456789abcdef0123456789abcdef")
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
	if err != nil || len(state.Devices) != 1 || state.Devices[0].Name != "Phone" || !state.Devices[0].Created.Equal(at) || len(state.Retired) != 1 {
		t.Fatalf("state %#v err %v", state, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}
}

func TestAFailedUpdateChangesNothing(t *testing.T) {
	saved, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("refused")
	err = saved.Update(func(state *State) error {
		state.Devices = append(state.Devices, Device{ID: "a1"})
		return refused
	})
	if !errors.Is(err, refused) {
		t.Fatalf("err %v", err)
	}
	if state, _ := saved.Read(); len(state.Devices) != 0 {
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
