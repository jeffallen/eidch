package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config represents the application configuration
type Config struct {
	Server  ServerConfig  `json:"server"`
	Profile string        `json:"profile"`
	Signing SigningConfig `json:"signing"`
	Storage StorageConfig `json:"storage"`
	Client  ClientConfig  `json:"client"`

	// Environment-specific settings
	ExternalURL          string `json:"external_url"`
	ClientID             string `json:"client_id"`
	VerificationMethodID string `json:"verification_method_id"`
	RequestObjectVersion string `json:"request_object_version"`
	ClientIDScheme       string `json:"client_id_scheme"`
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Port string `json:"port"`
	Host string `json:"host"`
}

// SigningConfig holds signing key configuration
type SigningConfig struct {
	PrivateKeyPEM string `json:"private_key_pem"`
	KeyID         string `json:"key_id"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Type               string        `json:"type"`
	DataDirectory      string        `json:"data_directory"`
	ExpirationDuration time.Duration `json:"expiration_duration"`
}

// ClientConfig holds client metadata configuration
type ClientConfig struct {
	Metadata map[string]interface{} `json:"metadata"`
}

// LoadConfig loads configuration from environment variables and defaults
func LoadConfig() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnvOrDefault("SERVER_PORT", "8080"),
			Host: getEnvOrDefault("SERVER_HOST", "localhost"),
		},
		Profile: getEnvOrDefault("PROFILE", "local"),
		Signing: SigningConfig{
			PrivateKeyPEM: os.Getenv("SIGNING_KEY"),
			KeyID:         os.Getenv("DID_VERIFICATION_METHOD"),
		},
		Storage: StorageConfig{
			Type:               getEnvOrDefault("STORAGE_TYPE", "memory"),
			DataDirectory:      getEnvOrDefault("STORAGE_DATA_DIR", "./data"),
			ExpirationDuration: getEnvDurationOrDefault("EXPIRATION_DURATION", 5*time.Minute),
		},
		ExternalURL:          getRequiredEnv("EXTERNAL_URL"),
		ClientID:             getRequiredEnv("VERIFIER_DID"),
		VerificationMethodID: getRequiredEnv("DID_VERIFICATION_METHOD"),
		RequestObjectVersion: getEnvOrDefault("REQUEST_OBJECT_VERSION", "1.0"),
		ClientIDScheme:       getEnvOrDefault("CLIENT_ID_SCHEME", "did"),
	}

	// Load client metadata from file if specified
	if metadataFile := os.Getenv("OPENID_CLIENT_METADATA_FILE"); metadataFile != "" {
		if err := loadClientMetadata(cfg, metadataFile); err != nil {
			return nil, fmt.Errorf("failed to load client metadata: %w", err)
		}
	} else {
		// Default client metadata
		cfg.Client.Metadata = map[string]interface{}{
			"client_id":   cfg.ClientID,
			"client_name": "EID-CH Verifier Agent",
		}
	}

	return cfg, nil
}

// getEnvOrDefault returns environment variable value or default
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getRequiredEnv returns environment variable value or panics if not set
func getRequiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("Required environment variable %s is not set", key))
	}
	return value
}

// getEnvDurationOrDefault parses environment variable as duration or returns default
func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getEnvIntOrDefault parses environment variable as int or returns default
func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// loadClientMetadata loads client metadata from JSON file
func loadClientMetadata(cfg *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}

	cfg.Client.Metadata = metadata
	return nil
}
