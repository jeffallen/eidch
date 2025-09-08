package issuer

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config represents the issuer configuration
type Config struct {
	Server     ServerConfig     `json:"server"`
	Storage    StorageConfig    `json:"storage"`
	Signing    SigningConfig    `json:"signing"`
	Metadata   MetadataConfig   `json:"metadata"`
	Nonce      NonceConfig      `json:"nonce"`
	Credential CredentialConfig `json:"credential"`

	// Core issuer settings
	ExternalURL string `json:"external_url"`
	IssuerID    string `json:"issuer_id"`
	Profile     string `json:"profile"`
}

// ServerConfig holds server configuration
type ServerConfig struct {
	Port string `json:"port"`
	Host string `json:"host"`
}

// StorageConfig holds storage configuration
type StorageConfig struct {
	Type            string        `json:"type"`
	DataDirectory   string        `json:"data_directory"`
	CleanupInterval time.Duration `json:"cleanup_interval"`
}

// SigningConfig holds signing configuration
type SigningConfig struct {
	PrivateKeyPEM      string `json:"private_key_pem"`
	VerificationMethod string `json:"verification_method"`
	Algorithm          string `json:"algorithm"`
}

// MetadataConfig holds issuer metadata
type MetadataConfig struct {
	CredentialsSupported []CredentialSupported `json:"credentials_supported"`
	DisplayInfo          DisplayInfo           `json:"display_info"`
}

// CredentialSupported represents a supported credential type
type CredentialSupported struct {
	ID                                   string               `json:"id"`
	Format                               string               `json:"format"`
	CryptographicBindingMethodsSupported []string             `json:"cryptographic_binding_methods_supported"`
	CredentialSigningAlgValuesSupported  []string             `json:"credential_signing_alg_values_supported"`
	ProofTypesSupported                  []string             `json:"proof_types_supported"`
	CredentialDefinition                 CredentialDefinition `json:"credential_definition"`
	Display                              []DisplayInfo        `json:"display"`
}

// CredentialDefinition defines the credential structure
type CredentialDefinition struct {
	Type   []string             `json:"type"`
	VCT    string               `json:"vct,omitempty"`
	Claims map[string]ClaimInfo `json:"claims,omitempty"`
}

// ClaimInfo describes a claim
type ClaimInfo struct {
	Mandatory bool          `json:"mandatory,omitempty"`
	Display   []DisplayInfo `json:"display,omitempty"`
}

// DisplayInfo holds display information
type DisplayInfo struct {
	Name   string `json:"name"`
	Locale string `json:"locale,omitempty"`
	Logo   string `json:"logo_uri,omitempty"`
}

// NonceConfig holds nonce-related settings
type NonceConfig struct {
	LifetimeSeconds int `json:"lifetime_seconds"`
}

// CredentialConfig holds credential-related settings
type CredentialConfig struct {
	DefaultExpirationHours int    `json:"default_expiration_hours"`
	DefaultFormat          string `json:"default_format"`
}

// LoadConfigFromEnv loads configuration from environment variables
func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Port: getEnvOrDefault("SERVER_PORT", "8080"),
			Host: getEnvOrDefault("SERVER_HOST", "localhost"),
		},
		Storage: StorageConfig{
			Type:            getEnvOrDefault("STORAGE_TYPE", "memory"),
			DataDirectory:   getEnvOrDefault("STORAGE_DATA_DIR", "./issuer-data"),
			CleanupInterval: getEnvDurationOrDefault("STORAGE_CLEANUP_INTERVAL", 1*time.Hour),
		},
		Signing: SigningConfig{
			PrivateKeyPEM:      os.Getenv("SIGNING_KEY"),
			VerificationMethod: getRequiredEnv("VERIFICATION_METHOD"),
			Algorithm:          getEnvOrDefault("SIGNING_ALGORITHM", "ES256"),
		},
		Metadata: MetadataConfig{
			DisplayInfo: DisplayInfo{
				Name:   getEnvOrDefault("ISSUER_DISPLAY_NAME", "EID-CH Issuer Go"),
				Locale: getEnvOrDefault("ISSUER_LOCALE", "en-US"),
				Logo:   os.Getenv("ISSUER_LOGO_URI"),
			},
		},
		Nonce: NonceConfig{
			LifetimeSeconds: getEnvIntOrDefault("NONCE_LIFETIME_SECONDS", 300), // 5 minutes
		},
		Credential: CredentialConfig{
			DefaultExpirationHours: getEnvIntOrDefault("CREDENTIAL_EXPIRATION_HOURS", 8760), // 1 year
			DefaultFormat:          getEnvOrDefault("CREDENTIAL_DEFAULT_FORMAT", "vc+sd-jwt"),
		},
		ExternalURL: getRequiredEnv("EXTERNAL_URL"),
		IssuerID:    getRequiredEnv("ISSUER_ID"),
		Profile:     getEnvOrDefault("PROFILE", "local"),
	}

	// Load credentials supported from file if specified
	if credentialsFile := os.Getenv("CREDENTIALS_SUPPORTED_FILE"); credentialsFile != "" {
		if err := loadCredentialsSupported(cfg, credentialsFile); err != nil {
			return nil, fmt.Errorf("failed to load credentials supported: %w", err)
		}
	} else {
		// Default credential types
		cfg.Metadata.CredentialsSupported = []CredentialSupported{
			{
				ID:                                   "example_sd_jwt",
				Format:                               "vc+sd-jwt",
				CryptographicBindingMethodsSupported: []string{"jwk"},
				CredentialSigningAlgValuesSupported:  []string{"ES256"},
				ProofTypesSupported:                  []string{"jwt"},
				CredentialDefinition: CredentialDefinition{
					Type: []string{"VerifiableCredential", "ExampleCredential"},
					VCT:  "https://example.com/example-credential",
					Claims: map[string]ClaimInfo{
						"given_name": {
							Mandatory: true,
							Display: []DisplayInfo{{
								Name:   "Given Name",
								Locale: "en-US",
							}},
						},
						"family_name": {
							Mandatory: true,
							Display: []DisplayInfo{{
								Name:   "Family Name",
								Locale: "en-US",
							}},
						},
						"email": {
							Mandatory: false,
							Display: []DisplayInfo{{
								Name:   "Email Address",
								Locale: "en-US",
							}},
						},
					},
				},
				Display: []DisplayInfo{{
					Name:   "Example Credential",
					Locale: "en-US",
				}},
			},
		}
	}

	return cfg, nil
}

// Helper functions
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getRequiredEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("Required environment variable %s is not set", key))
	}
	return value
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

func getEnvDurationOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// loadCredentialsSupported loads supported credentials from JSON file
func loadCredentialsSupported(cfg *Config, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var credentials []CredentialSupported
	if err := json.Unmarshal(data, &credentials); err != nil {
		return err
	}

	cfg.Metadata.CredentialsSupported = credentials
	return nil
}
