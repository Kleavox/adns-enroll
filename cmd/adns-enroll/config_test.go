package main

import (
	"bytes"
	"maps"
	"slices"
	"strings"
	"testing"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

var full = map[string]string{
	"ADGUARD_URL":        "http://host.docker.internal:3000",
	"ADGUARD_USERNAME":   "enroll",
	"ADGUARD_PASSWORD":   "secret",
	"DOH_HOST":           "dns.kleavox.xyz",
	"ADMIN_SUBJECTS":     " Pairwise-Owner_1 , other-sub ,",
	"PAWL_ISSUER":        "https://paw.kleavox.xyz/",
	"PAWL_CLIENT_ID":     "dns",
	"PAWL_CLIENT_SECRET": "client-secret",
	"PUBLIC_ORIGIN":      "https://enroll.kleavox.xyz/",
}

func TestAFullConfigurationIsRead(t *testing.T) {
	config, missing := load(env(full))
	if len(missing) != 0 {
		t.Fatalf("missing %v", missing)
	}
	if config.DataDir != "/data" || config.Listen != ":8080" || config.DoHHost != "dns.kleavox.xyz" ||
		!slices.Equal(config.Admins, []string{"Pairwise-Owner_1", "other-sub"}) ||
		config.Issuer != "https://paw.kleavox.xyz" || config.Origin != "https://enroll.kleavox.xyz" || config.signInMissing() != "" {
		t.Fatalf("config %#v", config)
	}
}

func TestMissingValuesAreNamedNeverShown(t *testing.T) {
	_, missing := load(env(map[string]string{"ADGUARD_PASSWORD": "secret"}))
	want := []string{"ADGUARD_URL", "ADGUARD_USERNAME", "DOH_HOST"}
	if !slices.Equal(missing, want) {
		t.Fatalf("missing %v", missing)
	}
	if strings.Contains(strings.Join(missing, " "), "secret") {
		t.Fatal("values are never printed")
	}
}

func TestWithoutPawlSettingsTheAppStartsAndSaysWhatIsMissing(t *testing.T) {
	for _, name := range []string{"PAWL_ISSUER", "PAWL_CLIENT_ID", "PAWL_CLIENT_SECRET", "PUBLIC_ORIGIN"} {
		partial := maps.Clone(full)
		delete(partial, name)
		config, missing := load(env(partial))
		if len(missing) != 0 {
			t.Fatalf("Pawl's settings are not required to start: %v", missing)
		}
		if config.signInMissing() != name {
			t.Fatalf("without %s: %q", name, config.signInMissing())
		}
	}
}

func TestSettingsFromBeforePawlAreNamedAsNoLongerRead(t *testing.T) {
	old := maps.Clone(full)
	old["ADMIN_EMAILS"] = "a@b.c"
	old["ACCESS_AUD"] = "aud"
	config, _ := load(env(old))
	if !slices.Equal(config.Retired, []string{"ADMIN_EMAILS", "ACCESS_AUD"}) {
		t.Fatalf("retired %v", config.Retired)
	}
}

func TestTheSessionKeyComesFromTheSecretWithoutBeingIt(t *testing.T) {
	config, _ := load(env(full))
	key := config.sessionKey()
	if len(key) != 32 || bytes.Contains(key, []byte(full["PAWL_CLIENT_SECRET"])) {
		t.Fatalf("key %x", key)
	}
	changed := maps.Clone(full)
	changed["PAWL_CLIENT_SECRET"] = "rotated"
	again, _ := load(env(changed))
	if bytes.Equal(again.sessionKey(), key) {
		t.Fatal("a new secret keeps the old sessions")
	}
}
