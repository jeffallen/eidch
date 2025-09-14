package storage

import (
	"fmt"
	"strings"

	"github.com/jeffallen/eiech/config"
)

// NewRepository creates a new Repository based on the configuration
func NewRepository(cfg *config.Config) (Repository, error) {
	switch strings.ToLower(cfg.Storage.Type) {
	case "memory":
		return NewMemoryStorage()
	case "jsonfile", "json":
		return NewJSONFileStorage(cfg.Storage.DataDirectory)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s (supported: memory, jsonfile)", cfg.Storage.Type)
	}
}

// NewWriteRepository creates a new WriteRepository based on the configuration
func NewWriteRepository(cfg *config.Config) (WriteRepository, error) {
	switch strings.ToLower(cfg.Storage.Type) {
	case "memory":
		return NewMemoryStorage()
	case "jsonfile", "json":
		return NewJSONFileStorage(cfg.Storage.DataDirectory)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s (supported: memory, jsonfile)", cfg.Storage.Type)
	}
}
