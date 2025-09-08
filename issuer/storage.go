package issuer

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Storage interface for credential offers and related data
type Storage interface {
	// Credential offers
	SaveCredentialOffer(offer *CredentialOffer) error
	GetCredentialOffer(id string) (*CredentialOffer, error)
	GetCredentialOfferByPreAuthCode(code string) (*CredentialOffer, error)
	GetCredentialOfferByAccessToken(token string) (*CredentialOffer, error)
	UpdateCredentialOffer(offer *CredentialOffer) error
	DeleteCredentialOffer(id string) error
	ListCredentialOffers() ([]*CredentialOffer, error)

	// Nonce management
	IsNonceUsed(nonce string) (bool, error)
	MarkNonceAsUsed(nonce string) error

	// Cleanup
	CleanupExpired() error
	Close() error
}

// NewStorage creates a new storage instance based on configuration
func NewStorage(cfg *Config) (Storage, error) {
	switch cfg.Storage.Type {
	case "memory":
		return NewMemoryStorage(), nil
	case "jsonfile":
		return NewJSONFileStorage(cfg.Storage.DataDirectory)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", cfg.Storage.Type)
	}
}

// MemoryStorage implements Storage using in-memory maps
type MemoryStorage struct {
	mu           sync.RWMutex
	offers       map[string]*CredentialOffer
	preAuthCodes map[string]string // preAuthCode -> offerID
	accessTokens map[string]string // accessToken -> offerID
	usedNonces   map[string]time.Time
}

// NewMemoryStorage creates a new memory storage instance
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		offers:       make(map[string]*CredentialOffer),
		preAuthCodes: make(map[string]string),
		accessTokens: make(map[string]string),
		usedNonces:   make(map[string]time.Time),
	}
}

func (ms *MemoryStorage) SaveCredentialOffer(offer *CredentialOffer) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if offer.ID == "" {
		return fmt.Errorf("offer ID cannot be empty")
	}

	offer.UpdatedAt = time.Now()
	if offer.CreatedAt.IsZero() {
		offer.CreatedAt = time.Now()
	}

	// Store the offer
	ms.offers[offer.ID] = offer

	// Index by pre-authorized code
	if offer.PreAuthorizedCode != "" {
		ms.preAuthCodes[offer.PreAuthorizedCode] = offer.ID
	}

	// Index by access token
	if offer.AccessToken != "" {
		ms.accessTokens[offer.AccessToken] = offer.ID
	}

	return nil
}

func (ms *MemoryStorage) GetCredentialOffer(id string) (*CredentialOffer, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	offer, exists := ms.offers[id]
	if !exists {
		return nil, nil
	}

	// Return a copy to avoid concurrent modification
	return ms.copyOffer(offer), nil
}

func (ms *MemoryStorage) GetCredentialOfferByPreAuthCode(code string) (*CredentialOffer, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	offerID, exists := ms.preAuthCodes[code]
	if !exists {
		return nil, nil
	}

	offer, exists := ms.offers[offerID]
	if !exists {
		return nil, nil
	}

	return ms.copyOffer(offer), nil
}

func (ms *MemoryStorage) GetCredentialOfferByAccessToken(token string) (*CredentialOffer, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	offerID, exists := ms.accessTokens[token]
	if !exists {
		return nil, nil
	}

	offer, exists := ms.offers[offerID]
	if !exists {
		return nil, nil
	}

	return ms.copyOffer(offer), nil
}

func (ms *MemoryStorage) UpdateCredentialOffer(offer *CredentialOffer) error {
	return ms.SaveCredentialOffer(offer) // Same as save for memory storage
}

func (ms *MemoryStorage) DeleteCredentialOffer(id string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	offer, exists := ms.offers[id]
	if !exists {
		return nil
	}

	// Remove from all indexes
	delete(ms.offers, id)
	if offer.PreAuthorizedCode != "" {
		delete(ms.preAuthCodes, offer.PreAuthorizedCode)
	}
	if offer.AccessToken != "" {
		delete(ms.accessTokens, offer.AccessToken)
	}

	return nil
}

func (ms *MemoryStorage) ListCredentialOffers() ([]*CredentialOffer, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	offers := make([]*CredentialOffer, 0, len(ms.offers))
	for _, offer := range ms.offers {
		offers = append(offers, ms.copyOffer(offer))
	}

	return offers, nil
}

func (ms *MemoryStorage) IsNonceUsed(nonce string) (bool, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	_, exists := ms.usedNonces[nonce]
	return exists, nil
}

func (ms *MemoryStorage) MarkNonceAsUsed(nonce string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	ms.usedNonces[nonce] = time.Now()
	return nil
}

func (ms *MemoryStorage) CleanupExpired() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	now := time.Now()

	// Clean up expired offers
	for id, offer := range ms.offers {
		if offer.IsExpired() {
			delete(ms.offers, id)
			if offer.PreAuthorizedCode != "" {
				delete(ms.preAuthCodes, offer.PreAuthorizedCode)
			}
			if offer.AccessToken != "" {
				delete(ms.accessTokens, offer.AccessToken)
			}
		}
	}

	// Clean up old nonces (older than 1 hour)
	for nonce, timestamp := range ms.usedNonces {
		if now.Sub(timestamp) > time.Hour {
			delete(ms.usedNonces, nonce)
		}
	}

	return nil
}

func (ms *MemoryStorage) Close() error {
	return nil
}

func (ms *MemoryStorage) copyOffer(original *CredentialOffer) *CredentialOffer {
	if original == nil {
		return nil
	}

	copy := *original

	// Deep copy the credential data map
	if original.CredentialData != nil {
		copy.CredentialData = make(map[string]interface{})
		for k, v := range original.CredentialData {
			copy.CredentialData[k] = v
		}
	}

	// Deep copy configuration override
	if original.ConfigurationOverride != nil {
		override := *original.ConfigurationOverride
		copy.ConfigurationOverride = &override
	}

	// Deep copy client agent info
	if original.ClientAgentInfo != nil {
		agentInfo := *original.ClientAgentInfo
		copy.ClientAgentInfo = &agentInfo
	}

	return &copy
}

// JSONFileStorage implements Storage using JSON files
type JSONFileStorage struct {
	mu      sync.RWMutex
	dataDir string
}

// NewJSONFileStorage creates a new JSON file storage instance
func NewJSONFileStorage(dataDir string) (*JSONFileStorage, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	return &JSONFileStorage{
		dataDir: dataDir,
	}, nil
}

func (jfs *JSONFileStorage) SaveCredentialOffer(offer *CredentialOffer) error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	if offer.ID == "" {
		return fmt.Errorf("offer ID cannot be empty")
	}

	offer.UpdatedAt = time.Now()
	if offer.CreatedAt.IsZero() {
		offer.CreatedAt = time.Now()
	}

	data, err := json.MarshalIndent(offer, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal offer: %w", err)
	}

	filename := filepath.Join(jfs.dataDir, "offer_"+offer.ID+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write offer file: %w", err)
	}

	return nil
}

func (jfs *JSONFileStorage) GetCredentialOffer(id string) (*CredentialOffer, error) {
	jfs.mu.RLock()
	defer jfs.mu.RUnlock()

	filename := filepath.Join(jfs.dataDir, "offer_"+id+".json")
	data, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read offer file: %w", err)
	}

	var offer CredentialOffer
	if err := json.Unmarshal(data, &offer); err != nil {
		return nil, fmt.Errorf("failed to unmarshal offer: %w", err)
	}

	return &offer, nil
}

func (jfs *JSONFileStorage) GetCredentialOfferByPreAuthCode(code string) (*CredentialOffer, error) {
	offers, err := jfs.ListCredentialOffers()
	if err != nil {
		return nil, err
	}

	for _, offer := range offers {
		if offer.PreAuthorizedCode == code {
			return offer, nil
		}
	}

	return nil, nil
}

func (jfs *JSONFileStorage) GetCredentialOfferByAccessToken(token string) (*CredentialOffer, error) {
	offers, err := jfs.ListCredentialOffers()
	if err != nil {
		return nil, err
	}

	for _, offer := range offers {
		if offer.AccessToken == token {
			return offer, nil
		}
	}

	return nil, nil
}

func (jfs *JSONFileStorage) UpdateCredentialOffer(offer *CredentialOffer) error {
	return jfs.SaveCredentialOffer(offer)
}

func (jfs *JSONFileStorage) DeleteCredentialOffer(id string) error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	filename := filepath.Join(jfs.dataDir, "offer_"+id+".json")
	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete offer file: %w", err)
	}

	return nil
}

func (jfs *JSONFileStorage) ListCredentialOffers() ([]*CredentialOffer, error) {
	jfs.mu.RLock()
	defer jfs.mu.RUnlock()

	pattern := filepath.Join(jfs.dataDir, "offer_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to glob offer files: %w", err)
	}

	var offers []*CredentialOffer
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // Skip files we can't read
		}

		var offer CredentialOffer
		if err := json.Unmarshal(data, &offer); err != nil {
			continue // Skip files we can't parse
		}

		offers = append(offers, &offer)
	}

	return offers, nil
}

func (jfs *JSONFileStorage) IsNonceUsed(nonce string) (bool, error) {
	filename := filepath.Join(jfs.dataDir, "nonce_"+nonce+".json")
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func (jfs *JSONFileStorage) MarkNonceAsUsed(nonce string) error {
	filename := filepath.Join(jfs.dataDir, "nonce_"+nonce+".json")
	data := map[string]interface{}{
		"nonce":   nonce,
		"used_at": time.Now(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal nonce data: %w", err)
	}

	return os.WriteFile(filename, jsonData, 0644)
}

func (jfs *JSONFileStorage) CleanupExpired() error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	// Clean up expired offers
	pattern := filepath.Join(jfs.dataDir, "offer_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to glob offer files: %w", err)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		var offer CredentialOffer
		if err := json.Unmarshal(data, &offer); err != nil {
			continue
		}

		if offer.IsExpired() {
			os.Remove(file)
		}
	}

	// Clean up old nonces
	noncePattern := filepath.Join(jfs.dataDir, "nonce_*.json")
	nonceFiles, err := filepath.Glob(noncePattern)
	if err != nil {
		return fmt.Errorf("failed to glob nonce files: %w", err)
	}

	for _, file := range nonceFiles {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		// Remove nonce files older than 1 hour
		if time.Since(info.ModTime()) > time.Hour {
			os.Remove(file)
		}
	}

	return nil
}

func (jfs *JSONFileStorage) Close() error {
	return nil
}
