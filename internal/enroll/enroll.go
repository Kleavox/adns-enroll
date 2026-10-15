package enroll

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

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

type Person struct {
	Sub   string
	Email string
	Name  string
}

var (
	ErrNotFound = errors.New("there is no such account")
	ErrState    = errors.New("the account is not in a state that allows this")
)

func random(size int) string {
	buffer := make([]byte, size)
	rand.Read(buffer)
	return hex.EncodeToString(buffer)
}

func Email(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func clientNameFor(account store.Account) string {
	who := account.Email
	if who == "" {
		who = account.Name
	}
	return who + " · " + account.ID
}

func legacyName(device store.Device) string {
	return device.Name + " · " + device.Owner + " · " + device.ID
}

func (s *Service) change(id string, edit func(*store.State, *store.Account) error) error {
	return s.Store.Update(func(state *store.State) error {
		index := slices.IndexFunc(state.Accounts, func(account store.Account) bool { return account.ID == id })
		if index < 0 {
			return ErrNotFound
		}
		return edit(state, &state.Accounts[index])
	})
}

func (s *Service) account(id string) (store.Account, error) {
	state, err := s.Store.Read()
	if err != nil {
		return store.Account{}, err
	}
	for _, account := range state.Accounts {
		if account.ID == id {
			return account, nil
		}
	}
	return store.Account{}, ErrNotFound
}

func remember(state *store.State, name string) {
	if !slices.Contains(state.Made, name) {
		state.Made = append(state.Made, name)
	}
}

func retire(state *store.State, ids []string) {
	for _, id := range ids {
		if !slices.Contains(state.Retired, id) {
			state.Retired = append(state.Retired, id)
		}
	}
}

func (s *Service) Migrate() error {
	return s.Store.Update(func(state *store.State) error {
		if len(state.Devices) == 0 {
			return nil
		}
		owners := map[string][]store.Device{}
		for _, device := range state.Devices {
			if device.Status == string(store.Approved) && device.ClientID != "" {
				owners[device.Owner] = append(owners[device.Owner], device)
				remember(state, legacyName(device))
			}
		}
		for _, owner := range slices.Sorted(maps.Keys(owners)) {
			devices := owners[owner]
			slices.SortFunc(devices, func(a, b store.Device) int { return b.Created.Compare(a.Created) })
			account := store.Account{
				ID:         random(8),
				Email:      Email(owner),
				Status:     store.Approved,
				ClientName: legacyName(devices[0]),
				Requested:  devices[len(devices)-1].Created,
				Decided:    devices[0].Decided,
			}
			for _, device := range devices {
				account.ClientIDs = append(account.ClientIDs, device.ClientID)
			}
			state.Accounts = append(state.Accounts, account)
		}
		state.Devices = nil
		return nil
	})
}

func (s *Service) restore(ctx context.Context, account store.Account) error {
	if err := s.DNS.Add(ctx, account.ClientName, account.ClientIDs[0]); err != nil {
		if s.DNS.SetIDs(ctx, account.ClientName, account.ClientIDs) != nil {
			return err
		}
	}
	if len(account.ClientIDs) > 1 {
		if err := s.DNS.SetIDs(ctx, account.ClientName, account.ClientIDs); err != nil {
			return err
		}
	}
	for _, id := range account.ClientIDs {
		if err := s.DNS.Allow(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Seen(ctx context.Context, person Person) (store.Account, error) {
	if strings.TrimSpace(person.Sub) == "" {
		return store.Account{}, errors.New("a person needs a subject")
	}
	var seen store.Account
	err := s.Store.Update(func(state *store.State) error {
		index := slices.IndexFunc(state.Accounts, func(account store.Account) bool { return account.Sub == person.Sub })
		if index < 0 {
			state.Accounts = append(state.Accounts, store.Account{
				ID:        random(8),
				Sub:       person.Sub,
				Email:     Email(person.Email),
				Name:      strings.TrimSpace(person.Name),
				Status:    store.Waiting,
				Requested: s.Now(),
			})
			index = len(state.Accounts) - 1
		}
		account := &state.Accounts[index]
		if email := Email(person.Email); email != "" {
			account.Email = email
		}
		if name := strings.TrimSpace(person.Name); name != "" {
			account.Name = name
		}
		seen = *account
		return nil
	})
	if err != nil || seen.Status != store.Ended {
		return seen, err
	}
	if err := s.restore(ctx, seen); err != nil {
		return seen, err
	}
	err = s.change(seen.ID, func(_ *store.State, account *store.Account) error {
		account.Status = store.Approved
		seen = *account
		return nil
	})
	return seen, err
}

func (s *Service) Approve(ctx context.Context, id string) error {
	account, err := s.account(id)
	if err != nil {
		return err
	}
	if account.Status != store.Waiting && account.Status != store.Denied {
		return ErrState
	}
	clientID := random(16)
	name := clientNameFor(account)
	if err := s.DNS.Add(ctx, name, clientID); err != nil {
		if s.DNS.SetIDs(ctx, name, []string{clientID}) != nil {
			return err
		}
	}
	if err := s.DNS.Allow(ctx, clientID); err != nil {
		s.DNS.Delete(ctx, name)
		return err
	}
	err = s.change(id, func(state *store.State, account *store.Account) error {
		if account.Status != store.Waiting && account.Status != store.Denied {
			return ErrState
		}
		account.Status = store.Approved
		account.ClientIDs = []string{clientID}
		account.ClientName = name
		account.Decided = s.Now()
		remember(state, name)
		return nil
	})
	if err != nil {
		s.DNS.Disallow(ctx, clientID)
		s.DNS.Delete(ctx, name)
	}
	return err
}

func (s *Service) Reject(id string) error {
	return s.change(id, func(_ *store.State, account *store.Account) error {
		if account.Status != store.Waiting {
			return ErrState
		}
		account.Status = store.Denied
		account.Decided = s.Now()
		return nil
	})
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	account, err := s.account(id)
	if err != nil {
		return err
	}
	if account.Status != store.Approved && account.Status != store.Ended {
		return ErrState
	}
	if len(account.ClientIDs) > 0 {
		if err := s.DNS.Disallow(ctx, account.ClientIDs...); err != nil {
			return err
		}
		s.DNS.Delete(ctx, account.ClientName)
	}
	return s.change(id, func(state *store.State, account *store.Account) error {
		retire(state, account.ClientIDs)
		account.Status = store.Denied
		account.ClientIDs = nil
		account.Decided = s.Now()
		return nil
	})
}

func (s *Service) Renew(ctx context.Context, id string) error {
	account, err := s.account(id)
	if err != nil {
		return err
	}
	if account.Status != store.Approved || len(account.ClientIDs) == 0 {
		return ErrState
	}
	old, fresh, name := account.ClientIDs, random(16), account.ClientName
	if err := s.DNS.SetIDs(ctx, name, append(slices.Clone(old), fresh)); err != nil {
		return err
	}
	if err := s.DNS.Allow(ctx, fresh); err != nil {
		s.DNS.SetIDs(ctx, name, old)
		return err
	}
	err = s.change(id, func(state *store.State, account *store.Account) error {
		if !slices.Equal(account.ClientIDs, old) {
			return ErrState
		}
		account.ClientIDs = []string{fresh}
		retire(state, old)
		return nil
	})
	if err != nil {
		s.DNS.Disallow(ctx, fresh)
		s.DNS.SetIDs(ctx, name, old)
		return err
	}
	s.DNS.SetIDs(ctx, name, []string{fresh})
	s.DNS.Disallow(ctx, old...)
	return nil
}

func (s *Service) Link(id, legacyID string) error {
	return s.Store.Update(func(state *store.State) error {
		index := slices.IndexFunc(state.Accounts, func(account store.Account) bool { return account.ID == id })
		old := slices.IndexFunc(state.Accounts, func(account store.Account) bool {
			return account.ID == legacyID && account.Sub == "" && account.Status == store.Approved
		})
		if index < 0 || old < 0 {
			return ErrNotFound
		}
		account, legacy := &state.Accounts[index], state.Accounts[old]
		if account.Sub == "" || account.Status != store.Waiting || account.Email != legacy.Email {
			return ErrState
		}
		account.Status = store.Approved
		account.ClientIDs = legacy.ClientIDs
		account.ClientName = legacy.ClientName
		account.Decided = s.Now()
		state.Accounts = slices.Delete(state.Accounts, old, old+1)
		return nil
	})
}

func (s *Service) Subjects() ([]string, error) {
	state, err := s.Store.Read()
	if err != nil {
		return nil, err
	}
	var subjects []string
	for _, account := range state.Accounts {
		if account.Status == store.Approved && account.Sub != "" {
			subjects = append(subjects, account.Sub)
		}
	}
	return subjects, nil
}

func (s *Service) EndMissing(ctx context.Context, asked, live []string) error {
	state, err := s.Store.Read()
	if err != nil {
		return err
	}
	var problems []error
	for _, account := range state.Accounts {
		if account.Status != store.Approved || account.Sub == "" || !slices.Contains(asked, account.Sub) || slices.Contains(live, account.Sub) {
			continue
		}
		if err := s.DNS.Disallow(ctx, account.ClientIDs...); err != nil {
			problems = append(problems, err)
			continue
		}
		s.DNS.Delete(ctx, account.ClientName)
		problems = append(problems, s.change(account.ID, func(_ *store.State, account *store.Account) error {
			account.Status = store.Ended
			return nil
		}))
	}
	return errors.Join(problems...)
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
	desired := map[string][]string{}
	var wanted, dropped []string
	for _, account := range state.Accounts {
		if account.Status == store.Approved && account.ClientName != "" && len(account.ClientIDs) > 0 {
			desired[account.ClientName] = account.ClientIDs
			wanted = append(wanted, account.ClientIDs...)
		} else {
			dropped = append(dropped, account.ClientIDs...)
		}
	}
	dropped = append(dropped, state.Retired...)
	var problems []error
	present := map[string][]string{}
	for _, client := range clients {
		if _, keep := desired[client.Name]; !keep && slices.Contains(state.Made, client.Name) {
			problems = append(problems, s.DNS.Delete(ctx, client.Name))
			continue
		}
		present[client.Name] = client.IDs
	}
	for _, name := range slices.Sorted(maps.Keys(desired)) {
		ids := desired[name]
		current, found := present[name]
		switch {
		case !found:
			if err := s.DNS.Add(ctx, name, ids[0]); err != nil {
				problems = append(problems, err)
				continue
			}
			if len(ids) > 1 {
				problems = append(problems, s.DNS.SetIDs(ctx, name, ids))
			}
		case !slices.Equal(current, ids):
			problems = append(problems, s.DNS.SetIDs(ctx, name, ids))
		}
	}
	for _, id := range wanted {
		if !slices.Contains(allowed, id) {
			problems = append(problems, s.DNS.Allow(ctx, id))
		}
	}
	if stale := slices.DeleteFunc(slices.Clone(allowed), func(id string) bool {
		return !slices.Contains(dropped, id) || slices.Contains(wanted, id)
	}); len(stale) > 0 {
		problems = append(problems, s.DNS.Disallow(ctx, stale...))
	}
	return errors.Join(problems...)
}
