package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	APIOrigin          string    `json:"apiOrigin"`
	ServerID           string    `json:"serverId"`
	NodeToken          string    `json:"nodeToken"`
	NodeTokenExpiresAt time.Time `json:"nodeTokenExpiresAt"`
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var value Config
	if err := json.Unmarshal(data, &value); err != nil {
		return Config{}, err
	}
	if !strings.HasPrefix(value.APIOrigin, "https://") || !strings.HasPrefix(value.ServerID, "srv_") ||
		!strings.HasPrefix(value.NodeToken, "rtn_") {
		return Config{}, errors.New("runtime configuration is invalid")
	}
	return value, nil
}

func Save(path string, value Config) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(temporary, path)
}
