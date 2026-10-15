package adguard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

const nobody = "192.0.2.1"

type Client struct {
	base     string
	user     string
	password string
	http     *http.Client
}

type Entry struct {
	Name string
	IDs  []string
}

func New(base, user, password string, client *http.Client) *Client {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &Client{base: strings.TrimSuffix(base, "/"), user: user, password: password, http: client}
}

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.base+"/control/"+path, body)
	if err != nil {
		return err
	}
	request.SetBasicAuth(c.user, c.password)
	if in != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("adguard %s: %w", path, err)
	}
	defer response.Body.Close()
	if response.StatusCode/100 != 2 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("adguard %s answered %d", path, response.StatusCode)
	}
	if out == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20))
		return err
	}
	return json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(out)
}

func (c *Client) raw(ctx context.Context) ([]map[string]any, error) {
	var listed struct {
		Clients []map[string]any `json:"clients"`
	}
	if err := c.call(ctx, http.MethodGet, "clients", nil, &listed); err != nil {
		return nil, err
	}
	return listed.Clients, nil
}

func (c *Client) Clients(ctx context.Context) ([]Entry, error) {
	listed, err := c.raw(ctx)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(listed))
	for _, client := range listed {
		name, _ := client["name"].(string)
		entries = append(entries, Entry{Name: name, IDs: texts(client["ids"])})
	}
	return entries, nil
}

func texts(value any) []string {
	items, _ := value.([]any)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func (c *Client) Add(ctx context.Context, name, id string) error {
	return c.call(ctx, http.MethodPost, "clients/add", map[string]any{
		"name":                        name,
		"ids":                         []string{id},
		"use_global_settings":         true,
		"use_global_blocked_services": true,
	}, nil)
}

func (c *Client) SetIDs(ctx context.Context, name string, ids []string) error {
	listed, err := c.raw(ctx)
	if err != nil {
		return err
	}
	for _, client := range listed {
		if client["name"] == name {
			client["ids"] = ids
			return c.call(ctx, http.MethodPost, "clients/update", map[string]any{"name": name, "data": client}, nil)
		}
	}
	return fmt.Errorf("adguard has no client named %s", name)
}

func (c *Client) Delete(ctx context.Context, name string) error {
	return c.call(ctx, http.MethodPost, "clients/delete", map[string]any{"name": name}, nil)
}

func (c *Client) access(ctx context.Context) (map[string]any, []string, error) {
	var list map[string]any
	if err := c.call(ctx, http.MethodGet, "access/list", nil, &list); err != nil {
		return nil, nil, err
	}
	if list == nil {
		list = map[string]any{}
	}
	return list, texts(list["allowed_clients"]), nil
}

func (c *Client) Allowed(ctx context.Context) ([]string, error) {
	_, allowed, err := c.access(ctx)
	return allowed, err
}

func (c *Client) Allow(ctx context.Context, id string) error {
	list, allowed, err := c.access(ctx)
	if err != nil {
		return err
	}
	if slices.Contains(allowed, id) {
		return nil
	}
	list["allowed_clients"] = append(slices.DeleteFunc(allowed, func(item string) bool { return item == nobody }), id)
	return c.call(ctx, http.MethodPost, "access/set", list, nil)
}

func (c *Client) Disallow(ctx context.Context, ids ...string) error {
	list, allowed, err := c.access(ctx)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(allowed), func(item string) bool { return slices.Contains(ids, item) })
	if len(kept) == len(allowed) {
		return nil
	}
	if len(kept) == 0 {
		kept = []string{nobody}
	}
	list["allowed_clients"] = kept
	return c.call(ctx, http.MethodPost, "access/set", list, nil)
}
