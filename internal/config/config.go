// Package config reads the exporter's settings from the environment and an
// optional YAML file.
package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	defaultRealm         = "US"
	defaultPollInterval  = 15 * time.Minute
	defaultListenAddress = ":10057"
	minPollInterval      = time.Minute
)

var labelName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

type Config struct {
	KeyID         string
	KeySecret     string
	Realm         string
	BaseURL       string // overrides Realm, for testing against a dev stack
	PollInterval  time.Duration
	ListenAddress string
	File          File
}

// File is HUSH_CONFIG_FILE.
type File struct {
	// Label name to the prefix of the tags it is read from.
	TagLabels map[string]string `yaml:"tag_labels"`
}

func Load() (Config, error) {
	c := Config{
		KeyID:         os.Getenv("HUSH_API_KEY_ID"),
		KeySecret:     os.Getenv("HUSH_API_KEY_SECRET"),
		Realm:         getenv("HUSH_REALM", defaultRealm),
		BaseURL:       os.Getenv("HUSH_BASE_URL"),
		ListenAddress: getenv("HUSH_LISTEN_ADDRESS", defaultListenAddress),
		PollInterval:  defaultPollInterval,
	}
	if c.KeyID == "" || c.KeySecret == "" {
		return c, fmt.Errorf("HUSH_API_KEY_ID and HUSH_API_KEY_SECRET are required")
	}
	if v := os.Getenv("HUSH_POLL_INTERVAL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return c, fmt.Errorf("HUSH_POLL_INTERVAL: %w", err)
		}
		if d < minPollInterval {
			return c, fmt.Errorf("HUSH_POLL_INTERVAL: at least %s", minPollInterval)
		}
		c.PollInterval = d
	}
	if path := os.Getenv("HUSH_CONFIG_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return c, err
		}
		if err := yaml.Unmarshal(data, &c.File); err != nil {
			return c, fmt.Errorf("%s: %w", path, err)
		}
	}
	for name, prefix := range c.File.TagLabels {
		if !labelName.MatchString(name) {
			return c, fmt.Errorf("tag_labels: %q is not a label name", name)
		}
		if prefix == "" {
			return c, fmt.Errorf("tag_labels: %s needs a prefix", name)
		}
	}
	return c, nil
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
