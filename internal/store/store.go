package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const File = "devices.json"

type Status string

const (
	Waiting  Status = "waiting"
	Approved Status = "approved"
	Rejected Status = "rejected"
)

type Device struct {
	ID       string    `json:"id"`
	Owner    string    `json:"owner"`
	Name     string    `json:"name"`
	Status   Status    `json:"status"`
	ClientID string    `json:"clientId,omitempty"`
	Created  time.Time `json:"created"`
	Decided  time.Time `json:"decided,omitzero"`
}

type State struct {
	Devices []Device `json:"devices"`
	Retired []string `json:"retired"`
}

type Store struct {
	path string
	mu   sync.Mutex
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{path: filepath.Join(dir, File)}, nil
}

func (s *Store) Read() (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

func (s *Store) read() (State, error) {
	state := State{Devices: []Device{}, Retired: []string{}}
	body, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return state, nil
	}
	if err != nil {
		return state, err
	}
	if err := json.Unmarshal(body, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (s *Store) Update(change func(*State) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, err := s.read()
	if err != nil {
		return err
	}
	if err := change(&state); err != nil {
		return err
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return s.write(body)
}

func (s *Store) write(body []byte) error {
	temporary := s.path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		os.Remove(temporary)
		return err
	}
	if err := file.Close(); err != nil {
		os.Remove(temporary)
		return err
	}
	if err := os.Rename(temporary, s.path); err != nil {
		os.Remove(temporary)
		return err
	}
	return nil
}
