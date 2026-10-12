package adguard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
)

type fake struct {
	mu      sync.Mutex
	clients []map[string]any
	access  map[string]any
	calls   []string
	fail    string
}

func newFake() *fake {
	return &fake{
		clients: []map[string]any{{"name": "Laptop by hand", "ids": []any{"manual0123"}, "use_global_settings": false, "filtering_enabled": false, "upstreams": []any{"9.9.9.9"}}},
		access:  map[string]any{"allowed_clients": []any{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "manual0123"}, "disallowed_clients": []any{}, "blocked_hosts": []any{"version.bind"}},
	}
}

func (f *fake) server(t *testing.T) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		if user, pass, ok := r.BasicAuth(); !ok || user != "enroll" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if f.fail == r.URL.Path {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		var body map[string]any
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
		}
		switch r.URL.Path {
		case "/control/clients":
			json.NewEncoder(w).Encode(map[string]any{"clients": f.clients, "auto_clients": []any{}, "supported_tags": []any{}})
		case "/control/clients/add":
			f.clients = append(f.clients, body)
		case "/control/clients/update":
			for index, client := range f.clients {
				if client["name"] == body["name"] {
					f.clients[index] = body["data"].(map[string]any)
				}
			}
		case "/control/clients/delete":
			f.clients = slices.DeleteFunc(f.clients, func(client map[string]any) bool { return client["name"] == body["name"] })
		case "/control/access/list":
			json.NewEncoder(w).Encode(f.access)
		case "/control/access/set":
			f.access = body
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return New(server.URL, "enroll", "secret", server.Client())
}

func (f *fake) allowed() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var list []string
	for _, item := range f.access["allowed_clients"].([]any) {
		list = append(list, item.(string))
	}
	return list
}

func (f *fake) client(name string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, client := range f.clients {
		if client["name"] == name {
			return client
		}
	}
	return nil
}

func TestAddingAClientUsesTheGlobalSettings(t *testing.T) {
	f := newFake()
	api := f.server(t)
	if err := api.Add(context.Background(), "Phone · owner@example.com · a1", "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	client := f.client("Phone · owner@example.com · a1")
	if client == nil || client["use_global_settings"] != true || client["use_global_blocked_services"] != true {
		t.Fatalf("client %#v", client)
	}
	if ids := client["ids"].([]any); len(ids) != 1 || ids[0] != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("ids %#v", ids)
	}
}

func TestChangingAnIDKeepsEveryOtherSettingOfTheClient(t *testing.T) {
	f := newFake()
	api := f.server(t)
	if err := api.SetIDs(context.Background(), "Laptop by hand", []string{"manual0123", "fresh4567"}); err != nil {
		t.Fatal(err)
	}
	client := f.client("Laptop by hand")
	if client["use_global_settings"] != false || client["filtering_enabled"] != false || client["upstreams"].([]any)[0] != "9.9.9.9" {
		t.Fatalf("settings were lost: %#v", client)
	}
	if ids := client["ids"].([]any); len(ids) != 2 || ids[1] != "fresh4567" {
		t.Fatalf("ids %#v", ids)
	}
	if err := api.SetIDs(context.Background(), "Nobody", []string{"x"}); err == nil {
		t.Fatal("a missing client is an error")
	}
}

func TestAllowingTouchesOnlyTheGivenID(t *testing.T) {
	f := newFake()
	api := f.server(t)
	ctx := context.Background()
	if err := api.Allow(ctx, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	if err := api.Allow(ctx, "0123456789abcdef0123456789abcdef"); err != nil {
		t.Fatal(err)
	}
	want := []string{"100.64.0.0/10", "fd7a:115c:a1e0::/48", "manual0123", "0123456789abcdef0123456789abcdef"}
	if got := f.allowed(); !slices.Equal(got, want) {
		t.Fatalf("allowed %v", got)
	}
	if err := api.Disallow(ctx, "0123456789abcdef0123456789abcdef", "notthere"); err != nil {
		t.Fatal(err)
	}
	if got := f.allowed(); !slices.Equal(got, want[:3]) {
		t.Fatalf("allowed %v", got)
	}
	f.mu.Lock()
	hosts := f.access["blocked_hosts"].([]any)
	f.mu.Unlock()
	if len(hosts) != 1 || hosts[0] != "version.bind" {
		t.Fatalf("the rest of the access list changed: %#v", hosts)
	}
}

func TestDeletingAClientAndListingClients(t *testing.T) {
	f := newFake()
	api := f.server(t)
	ctx := context.Background()
	if err := api.Add(ctx, "Phone", "abc"); err != nil {
		t.Fatal(err)
	}
	clients, err := api.Clients(ctx)
	if err != nil || len(clients) != 2 || clients[1].Name != "Phone" || !slices.Equal(clients[1].IDs, []string{"abc"}) {
		t.Fatalf("clients %#v err %v", clients, err)
	}
	if err := api.Delete(ctx, "Phone"); err != nil {
		t.Fatal(err)
	}
	if f.client("Phone") != nil {
		t.Fatal("the client is still there")
	}
}

func TestAFailureSaysWhereWithoutTheBodyOfSecrets(t *testing.T) {
	f := newFake()
	api := f.server(t)
	f.fail = "/control/access/set"
	err := api.Allow(context.Background(), "abc")
	if err == nil || !strings.Contains(err.Error(), "access/set") || !strings.Contains(err.Error(), "500") {
		t.Fatalf("err %v", err)
	}
	wrong := New(strings.TrimSuffix(api.base, "/"), "enroll", "wrong", nil)
	if _, err := wrong.Clients(context.Background()); err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong") {
		t.Fatalf("err %v", err)
	}
}
