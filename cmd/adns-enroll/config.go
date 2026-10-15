package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
)

type config struct {
	AdGuardURL      string
	AdGuardUser     string
	AdGuardPassword string
	DoHHost         string
	Admins          []string
	Issuer          string
	ClientID        string
	ClientSecret    string
	Origin          string
	DataDir         string
	Listen          string
	Retired         []string
}

func load(getenv func(string) string) (config, []string) {
	value := func(name string) string { return strings.TrimSpace(getenv(name)) }
	c := config{
		AdGuardURL:      value("ADGUARD_URL"),
		AdGuardUser:     value("ADGUARD_USERNAME"),
		AdGuardPassword: getenv("ADGUARD_PASSWORD"),
		DoHHost:         value("DOH_HOST"),
		Issuer:          strings.TrimSuffix(value("PAWL_ISSUER"), "/"),
		ClientID:        value("PAWL_CLIENT_ID"),
		ClientSecret:    getenv("PAWL_CLIENT_SECRET"),
		Origin:          strings.TrimSuffix(value("PUBLIC_ORIGIN"), "/"),
		DataDir:         value("DATA_DIR"),
		Listen:          value("LISTEN"),
	}
	for admin := range strings.SplitSeq(getenv("ADMIN_SUBJECTS"), ",") {
		if admin = strings.TrimSpace(admin); admin != "" {
			c.Admins = append(c.Admins, admin)
		}
	}
	for _, old := range []string{"ADMIN_EMAILS", "ACCESS_TEAM", "ACCESS_AUD"} {
		if value(old) != "" {
			c.Retired = append(c.Retired, old)
		}
	}
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	var missing []string
	for _, required := range []struct {
		name string
		set  bool
	}{
		{"ADGUARD_URL", c.AdGuardURL != ""},
		{"ADGUARD_USERNAME", c.AdGuardUser != ""},
		{"ADGUARD_PASSWORD", c.AdGuardPassword != ""},
		{"DOH_HOST", c.DoHHost != ""},
	} {
		if !required.set {
			missing = append(missing, required.name)
		}
	}
	return c, missing
}

func (c config) signInMissing() string {
	for _, setting := range []struct {
		name string
		set  bool
	}{
		{"PAWL_ISSUER", c.Issuer != ""},
		{"PAWL_CLIENT_ID", c.ClientID != ""},
		{"PAWL_CLIENT_SECRET", c.ClientSecret != ""},
		{"PUBLIC_ORIGIN", c.Origin != ""},
	} {
		if !setting.set {
			return setting.name
		}
	}
	return ""
}

func (c config) sessionKey() []byte {
	signer := hmac.New(sha256.New, []byte(c.ClientSecret))
	signer.Write([]byte("adns-enroll session"))
	return signer.Sum(nil)
}
