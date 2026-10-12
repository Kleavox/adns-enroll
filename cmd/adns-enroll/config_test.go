package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

var full = map[string]string{
	"ADGUARD_URL":      "http://host.docker.internal:3000",
	"ADGUARD_USERNAME": "enroll",
	"ADGUARD_PASSWORD": "secret",
	"DOH_HOST":         "dns.kleavox.xyz",
	"ADMIN_EMAILS":     " Admin@Example.com , other@example.com ,",
	"ACCESS_TEAM":      "kleavox.cloudflareaccess.com",
	"ACCESS_AUD":       "aud-123",
}

func TestAFullConfigurationIsRead(t *testing.T) {
	config, missing := load(env(full))
	if len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	if config.DataDir != "/data" || config.Listen != ":8080" || !slices.Equal(config.Admins, []string{"admin@example.com", "other@example.com"}) || config.DoHHost != "dns.kleavox.xyz" {
		t.Fatalf("config %#v", config)
	}
}

func TestMissingValuesAreNamedNeverShown(t *testing.T) {
	_, missing := load(env(map[string]string{"ADGUARD_PASSWORD": "secret"}))
	want := []string{"ADGUARD_URL", "ADGUARD_USERNAME", "DOH_HOST", "ADMIN_EMAILS"}
	if !slices.Equal(missing, want) {
		t.Fatalf("missing %v", missing)
	}
	if strings.Contains(strings.Join(missing, " "), "secret") {
		t.Fatal("values are never printed")
	}
}

func TestWithoutTheAccessSettingsOnlyTheHealthCheckAnswers(t *testing.T) {
	partial := map[string]string{}
	for key, value := range full {
		partial[key] = value
	}
	delete(partial, "ACCESS_AUD")
	config, missing := load(env(partial))
	if len(missing) != 0 {
		t.Fatalf("the access settings are not required to start: %v", missing)
	}
	identity := config.identity()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := identity.Email(r); err == nil || !strings.Contains(err.Error(), "ACCESS_AUD") {
		t.Fatalf("err %v", err)
	}
}
