package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Setenv("HUSH_API_KEY_ID", "id")
	t.Setenv("HUSH_API_KEY_SECRET", "secret")
	t.Setenv("HUSH_SOURCES", "certificates, identity_keys,")
	file := filepath.Join(t.TempDir(), "c.yaml")
	_ = os.WriteFile(file, []byte("tag_labels:\n  team: \"team:\"\n"), 0o600)
	t.Setenv("HUSH_CONFIG_FILE", file)

	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Sources, []string{"certificates", "identity_keys"}) || c.Realm != "US" {
		t.Errorf("config = %+v", c)
	}
	if c.File.TagLabels["team"] != "team:" {
		t.Errorf("tag_labels = %v", c.File.TagLabels)
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Setenv("HUSH_API_KEY_ID", "id")
	t.Setenv("HUSH_API_KEY_SECRET", "")
	if _, err := Load(); err == nil {
		t.Error("missing secret accepted")
	}
}
