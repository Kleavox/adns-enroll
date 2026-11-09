package main

import (
	"bytes"
	"encoding/hex"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

func env(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

var full = map[string]string{
	"ADGUARD_URL":        "http://host.docker.internal:3000",
	"ADGUARD_USERNAME":   "enroll",
	"ADGUARD_PASSWORD":   "secret",
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
	if config.DataDir != "/data" || config.Listen != ":8080" || len(config.Retired) != 0 ||
		!slices.Equal(config.Admins, []string{"Pairwise-Owner_1", "other-sub"}) ||
		config.Issuer != "https://paw.kleavox.xyz" || config.Origin != "https://enroll.kleavox.xyz" || config.signInMissing() != "" {
		t.Fatalf("config %#v", config)
	}
}

func TestMissingValuesAreNamedNeverShown(t *testing.T) {
	_, missing := load(env(map[string]string{"ADGUARD_PASSWORD": "secret"}))
	want := []string{"ADGUARD_URL", "ADGUARD_USERNAME"}
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

func TestSettingsNoLongerReadAreNamedWithWhereTheyComeFromNow(t *testing.T) {
	old := maps.Clone(full)
	old["ADMIN_EMAILS"] = "a@b.c"
	old["ACCESS_AUD"] = "aud"
	old["DOH_HOST"] = "dns.kleavox.xyz"
	config, missing := load(env(old))
	if len(missing) != 0 || len(config.Retired) != 3 {
		t.Fatalf("missing %v retired %q", missing, config.Retired)
	}
	for index, name := range []string{"ADMIN_EMAILS", "ACCESS_AUD", "DOH_HOST"} {
		if !strings.HasPrefix(config.Retired[index], name+" is no longer read; ") {
			t.Errorf("retired %q", config.Retired[index])
		}
	}
	if !strings.Contains(config.Retired[1], "Pawl") || !strings.Contains(config.Retired[2], "AdGuard's encryption settings") || strings.Contains(strings.Join(config.Retired, " "), "dns.kleavox.xyz") {
		t.Fatalf("retired %q", config.Retired)
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

func TestWithoutASessionKeyTheOldDerivationFromTheSecretStaysByteForByte(t *testing.T) {
	changed := maps.Clone(full)
	changed["PAWL_CLIENT_SECRET"] = "client-secret"
	config, _ := load(env(changed))
	if got := hex.EncodeToString(config.sessionKey()); got != "a2ec5b41b0fc6b51d8ec2a8b28ef70d860c9e16654371abb7f9847e51466656c" {
		t.Fatalf("key %s", got)
	}
	if !config.sessionTiedToSecret() {
		t.Fatal("sessions are tied to the secret and the app says so")
	}
}

func TestASessionKeySurvivesANewClientSecret(t *testing.T) {
	keyed := maps.Clone(full)
	keyed["SESSION_KEY"] = " a long random value that the operator chose for sessions "
	config, _ := load(env(keyed))
	key := config.sessionKey()
	secretKey := func() []byte { c, _ := load(env(full)); return c.sessionKey() }()
	if len(key) != 32 || bytes.Equal(key, secretKey) || bytes.Contains(key, []byte("a long random value")) || config.sessionTiedToSecret() || len(config.Problems) != 0 {
		t.Fatalf("key %x problems %q", key, config.Problems)
	}
	keyed["PAWL_CLIENT_SECRET"] = "rotated"
	again, _ := load(env(keyed))
	if !bytes.Equal(again.sessionKey(), key) {
		t.Fatal("a new client secret signed everyone out")
	}
	keyed["SESSION_KEY"] = "another long random value that the operator chose later"
	other, _ := load(env(keyed))
	if bytes.Equal(other.sessionKey(), key) {
		t.Fatal("a new session key keeps the old sessions")
	}
}

func TestAShortSessionKeyIsAProblemNamedNeverShown(t *testing.T) {
	short := maps.Clone(full)
	short["SESSION_KEY"] = "too short"
	config, missing := load(env(short))
	if len(missing) != 0 || len(config.Problems) != 1 || !strings.HasPrefix(config.Problems[0], "SESSION_KEY") || strings.Contains(config.Problems[0], "too short") {
		t.Fatalf("missing %v problems %q", missing, config.Problems)
	}
}

func TestTheCardsAdGuardLimitHasADefaultBelowPawlsAndMustBeADuration(t *testing.T) {
	config, _ := load(env(full))
	if config.CardTimeout != 4*time.Second || len(config.Problems) != 0 {
		t.Fatalf("timeout %v problems %q", config.CardTimeout, config.Problems)
	}
	set := maps.Clone(full)
	set["CARD_ADGUARD_TIMEOUT"] = "1500ms"
	config, _ = load(env(set))
	if config.CardTimeout != 1500*time.Millisecond || len(config.Problems) != 0 {
		t.Fatalf("timeout %v problems %q", config.CardTimeout, config.Problems)
	}
	for _, bad := range []string{"soon", "0s", "-3s", "4"} {
		set["CARD_ADGUARD_TIMEOUT"] = bad
		config, _ = load(env(set))
		if len(config.Problems) != 1 || !strings.HasPrefix(config.Problems[0], "CARD_ADGUARD_TIMEOUT") {
			t.Errorf("%q: problems %q", bad, config.Problems)
		}
	}
}
