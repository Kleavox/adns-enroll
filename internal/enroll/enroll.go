package enroll

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Kleavox/adns-enroll/internal/adguard"
	"github.com/Kleavox/adns-enroll/internal/store"
)

type AdGuard interface {
	Clients(ctx context.Context) ([]adguard.Entry, error)
	Add(ctx context.Context, name, id string) error
	SetIDs(ctx context.Context, name string, ids []string) error
	Delete(ctx context.Context, name string) error
	Allowed(ctx context.Context) ([]string, error)
	Allow(ctx context.Context, id string) error
	Disallow(ctx context.Context, ids ...string) error
}

type Service struct {
	Store *store.Store
	DNS   AdGuard
	Now   func() time.Time
}

var (
	ErrNotFound = errors.New("there is no such device")
	ErrState    = errors.New("the device is not in a state that allows this")
)

type Invalid string

func (i Invalid) Error() string { return string(i) }

const maxName = 40

func random(size int) string {
	buffer := make([]byte, size)
	rand.Read(buffer)
	return hex.EncodeToString(buffer)
}

func ClientName(device store.Device) string {
	return device.Name + " · " + device.Owner + " · " + device.ID
}

func Owner(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func cleanName(name string) (string, error) {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return "", Invalid("Give the device a name, such as Phone.")
	case utf8.RuneCountInString(name) > maxName:
		return "", Invalid(fmt.Sprintf("A device name is at most %d characters.", maxName))
	case strings.ContainsFunc(name, unicode.IsControl):
		return "", Invalid("A device name is one line of text.")
	}
	return name, nil
}

func (s *Service) Request(owner, name string) (store.Device, error) {
	owner = Owner(owner)
	if owner == "" {
		return store.Device{}, Invalid("A request needs a signed-in person.")
	}
	name, err := cleanName(name)
	if err != nil {
		return store.Device{}, err
	}
	device := store.Device{ID: random(8), Owner: owner, Name: name, Status: store.Waiting, Created: s.Now()}
	err = s.Store.Update(func(state *store.State) error {
		state.Devices = append(state.Devices, device)
		return nil
	})
	return device, err
}

func (s *Service) device(id string) (store.Device, error) {
	state, err := s.Store.Read()
	if err != nil {
		return store.Device{}, err
	}
	for _, device := range state.Devices {
		if device.ID == id {
			return device, nil
		}
	}
	return store.Device{}, ErrNotFound
}

func (s *Service) change(id string, edit func(*store.State, int) error) error {
	return s.Store.Update(func(state *store.State) error {
		index := slices.IndexFunc(state.Devices, func(device store.Device) bool { return device.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		return edit(state, index)
	})
}

func (s *Service) Approve(ctx context.Context, id string) error {
	device, err := s.device(id)
	if err != nil {
		return err
	}
	if device.Status != store.Waiting {
		return ErrState
	}
	clientID := random(16)
	name := ClientName(device)
	if err := s.DNS.Add(ctx, name, clientID); err != nil {
		if s.DNS.SetIDs(ctx, name, []string{clientID}) != nil {
			return err
		}
	}
	if err := s.DNS.Allow(ctx, clientID); err != nil {
		s.DNS.Delete(ctx, name)
		return err
	}
	err = s.change(id, func(state *store.State, index int) error {
		if state.Devices[index].Status != store.Waiting {
			return ErrState
		}
		state.Devices[index].Status = store.Approved
		state.Devices[index].ClientID = clientID
		state.Devices[index].Decided = s.Now()
		return nil
	})
	if err != nil {
		s.DNS.Disallow(ctx, clientID)
		s.DNS.Delete(ctx, name)
	}
	return err
}

func (s *Service) Reject(id string) error {
	return s.change(id, func(state *store.State, index int) error {
		if state.Devices[index].Status != store.Waiting {
			return ErrState
		}
		state.Devices[index].Status = store.Rejected
		state.Devices[index].Decided = s.Now()
		return nil
	})
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	device, err := s.device(id)
	if err != nil {
		return err
	}
	return s.drop(ctx, device)
}

func (s *Service) Remove(ctx context.Context, owner, id string) error {
	device, err := s.device(id)
	if err != nil {
		return err
	}
	if device.Owner != Owner(owner) {
		return ErrNotFound
	}
	return s.drop(ctx, device)
}

func (s *Service) drop(ctx context.Context, device store.Device) error {
	if device.ClientID != "" {
		if err := s.DNS.Disallow(ctx, device.ClientID); err != nil {
			return err
		}
		s.DNS.Delete(ctx, ClientName(device))
	}
	return s.change(device.ID, func(state *store.State, index int) error {
		state.Devices = slices.Delete(state.Devices, index, index+1)
		if device.ClientID != "" && !slices.Contains(state.Retired, device.ClientID) {
			state.Retired = append(state.Retired, device.ClientID)
		}
		return nil
	})
}

func (s *Service) Renew(ctx context.Context, owner, id string) error {
	device, err := s.device(id)
	if err != nil {
		return err
	}
	if device.Owner != Owner(owner) {
		return ErrNotFound
	}
	if device.Status != store.Approved {
		return ErrState
	}
	old, fresh, name := device.ClientID, random(16), ClientName(device)
	if err := s.DNS.SetIDs(ctx, name, []string{old, fresh}); err != nil {
		return err
	}
	if err := s.DNS.Allow(ctx, fresh); err != nil {
		s.DNS.SetIDs(ctx, name, []string{old})
		return err
	}
	err = s.change(id, func(state *store.State, index int) error {
		if state.Devices[index].ClientID != old {
			return ErrState
		}
		state.Devices[index].ClientID = fresh
		state.Retired = append(state.Retired, old)
		return nil
	})
	if err != nil {
		s.DNS.Disallow(ctx, fresh)
		s.DNS.SetIDs(ctx, name, []string{old})
		return err
	}
	s.DNS.SetIDs(ctx, name, []string{fresh})
	s.DNS.Disallow(ctx, old)
	return nil
}

func (s *Service) Reconcile(ctx context.Context) error {
	state, err := s.Store.Read()
	if err != nil {
		return err
	}
	clients, err := s.DNS.Clients(ctx)
	if err != nil {
		return err
	}
	allowed, err := s.DNS.Allowed(ctx)
	if err != nil {
		return err
	}
	byName := map[string][]string{}
	for _, client := range clients {
		byName[client.Name] = client.IDs
	}
	var problems []error
	for _, device := range state.Devices {
		if device.Status != store.Approved || device.ClientID == "" {
			continue
		}
		name, want := ClientName(device), []string{device.ClientID}
		if ids, found := byName[name]; !found {
			problems = append(problems, s.DNS.Add(ctx, name, device.ClientID))
		} else if !slices.Equal(ids, want) {
			problems = append(problems, s.DNS.SetIDs(ctx, name, want))
		}
		if !slices.Contains(allowed, device.ClientID) {
			problems = append(problems, s.DNS.Allow(ctx, device.ClientID))
		}
	}
	retired := func(id string) bool { return slices.Contains(state.Retired, id) }
	if stale := slices.DeleteFunc(slices.Clone(allowed), func(id string) bool { return !retired(id) }); len(stale) > 0 {
		problems = append(problems, s.DNS.Disallow(ctx, stale...))
	}
	for _, client := range clients {
		kept := slices.DeleteFunc(slices.Clone(client.IDs), retired)
		switch {
		case len(kept) == len(client.IDs):
		case len(kept) == 0:
			problems = append(problems, s.DNS.Delete(ctx, client.Name))
		default:
			problems = append(problems, s.DNS.SetIDs(ctx, client.Name, kept))
		}
	}
	return errors.Join(problems...)
}
