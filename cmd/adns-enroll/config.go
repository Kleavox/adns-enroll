package main

import (
	"net/http"
	"strings"

	"github.com/Kleavox/adns-enroll/internal/access"
	"github.com/Kleavox/adns-enroll/internal/web"
)

type config struct {
	AdGuardURL      string
	AdGuardUser     string
	AdGuardPassword string
	DoHHost         string
	Admins          []string
	AccessTeam      string
	AccessAUD       string
	DataDir         string
	Listen          string
}

func load(getenv func(string) string) (config, []string) {
	value := func(name string) string { return strings.TrimSpace(getenv(name)) }
	c := config{
		AdGuardURL:      value("ADGUARD_URL"),
		AdGuardUser:     value("ADGUARD_USERNAME"),
		AdGuardPassword: getenv("ADGUARD_PASSWORD"),
		DoHHost:         value("DOH_HOST"),
		AccessTeam:      value("ACCESS_TEAM"),
		AccessAUD:       value("ACCESS_AUD"),
		DataDir:         value("DATA_DIR"),
		Listen:          value("LISTEN"),
	}
	for admin := range strings.SplitSeq(getenv("ADMIN_EMAILS"), ",") {
		if admin = strings.ToLower(strings.TrimSpace(admin)); admin != "" {
			c.Admins = append(c.Admins, admin)
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
		{"ADMIN_EMAILS", len(c.Admins) > 0},
	} {
		if !required.set {
			missing = append(missing, required.name)
		}
	}
	return c, missing
}

type notSetUp string

func (n notSetUp) Email(*http.Request) (string, error) {
	return "", web.Unready("Sign-in is not set up yet: " + string(n) + " is missing.")
}

func (c config) identity() web.Identity {
	switch {
	case c.AccessTeam == "":
		return notSetUp("ACCESS_TEAM")
	case c.AccessAUD == "":
		return notSetUp("ACCESS_AUD")
	}
	return access.New(c.AccessTeam, c.AccessAUD)
}
