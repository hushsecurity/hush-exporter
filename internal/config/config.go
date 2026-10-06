// Package config reads the exporter's settings.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	defaultRealm         = "US"
	defaultListenAddress = ":10057"
)

type Config struct {
	KeyID         string
	KeySecret     string
	Realm         string
	BaseURL       string // overrides Realm
	Sources       []string
	ListenAddress string
	File          File
}

// File is HUSH_CONFIG_FILE.
type File struct {
	TagLabels map[string]string `yaml:"tag_labels"`
}

func Load() (Config, error) {
	c := Config{
		KeyID:         os.Getenv("HUSH_API_KEY_ID"),
		KeySecret:     os.Getenv("HUSH_API_KEY_SECRET"),
		Realm:         getenv("HUSH_REALM", defaultRealm),
		BaseURL:       os.Getenv("HUSH_BASE_URL"),
		ListenAddress: getenv("HUSH_LISTEN_ADDRESS", defaultListenAddress),
	}
	if c.KeyID == "" || c.KeySecret == "" {
		return c, fmt.Errorf("HUSH_API_KEY_ID and HUSH_API_KEY_SECRET are required")
	}
	if v := os.Getenv("HUSH_SOURCES"); v != "" {
		for _, source := range strings.Split(v, ",") {
			if source = strings.TrimSpace(source); source != "" {
				c.Sources = append(c.Sources, source)
			}
		}
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
	return c, nil
}

func getenv(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
