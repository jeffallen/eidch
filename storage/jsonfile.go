package storage

import (
	"eidch-verifier-agent-oid4vp-go/domain"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// JSONFileStorage implements Repository using JSON files in a directory
type JSONFileStorage struct {
	mu      sync.RWMutex
	dataDir string
}

// NewJSONFileStorage creates a new JSON file storage instance
func NewJSONFileStorage(dataDir string) (*JSONFileStorage, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory %s: %w", dataDir, err)
	}

	return &JSONFileStorage{
		dataDir: dataDir,
	}, nil
}

// Save stores a ManagementEntity as a JSON file
func (jfs *JSONFileStorage) Save(entity *domain.ManagementEntity) error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	if entity.ID == "" {
		return fmt.Errorf("entity ID cannot be empty")
	}

	entity.UpdatedAt = time.Now()

	// Marshal entity to JSON
	data, err := json.MarshalIndent(entity, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal entity: %w", err)
	}

	// Write to file
	filename := filepath.Join(jfs.dataDir, entity.ID+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write entity file: %w", err)
	}

	return nil
}

// FindByID retrieves a ManagementEntity by reading its JSON file
func (jfs *JSONFileStorage) FindByID(id string) (*domain.ManagementEntity, error) {
	jfs.mu.RLock()
	defer jfs.mu.RUnlock()

	if id == "" {
		return nil, fmt.Errorf("entity ID cannot be empty")
	}

	filename := filepath.Join(jfs.dataDir, id+".json")

	// Check if file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, nil // Not found, but not an error
	} else if err != nil {
		return nil, fmt.Errorf("failed to stat entity file: %w", err)
	}

	// Read file
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read entity file: %w", err)
	}

	// Unmarshal JSON
	var entity domain.ManagementEntity
	if err := json.Unmarshal(data, &entity); err != nil {
		return nil, fmt.Errorf("failed to unmarshal entity: %w", err)
	}

	return &entity, nil
}

// Delete removes a ManagementEntity by deleting its JSON file
func (jfs *JSONFileStorage) Delete(id string) error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	if id == "" {
		return fmt.Errorf("entity ID cannot be empty")
	}

	filename := filepath.Join(jfs.dataDir, id+".json")

	// Remove file, ignore if it doesn't exist
	err := os.Remove(filename)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete entity file: %w", err)
	}

	return nil
}

// CleanupExpired removes expired entities by scanning all files
func (jfs *JSONFileStorage) CleanupExpired() error {
	jfs.mu.Lock()
	defer jfs.mu.Unlock()

	// Read all JSON files in the directory
	entries, err := os.ReadDir(jfs.dataDir)
	if err != nil {
		return fmt.Errorf("failed to read data directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			filename := filepath.Join(jfs.dataDir, entry.Name())

			// Read and check if expired
			data, err := os.ReadFile(filename)
			if err != nil {
				continue // Skip files we can't read
			}

			var entity domain.ManagementEntity
			if err := json.Unmarshal(data, &entity); err != nil {
				continue // Skip files we can't parse
			}

			if entity.IsExpired() {
				os.Remove(filename) // Ignore errors on cleanup
			}
		}
	}

	return nil
}

// List returns all ManagementEntities by reading all JSON files
func (jfs *JSONFileStorage) List() ([]*domain.ManagementEntity, error) {
	jfs.mu.RLock()
	defer jfs.mu.RUnlock()

	var entities []*domain.ManagementEntity

	// Read all JSON files in the directory
	entries, err := os.ReadDir(jfs.dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read data directory: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".json" {
			filename := filepath.Join(jfs.dataDir, entry.Name())

			// Read file
			data, err := os.ReadFile(filename)
			if err != nil {
				continue // Skip files we can't read
			}

			// Unmarshal JSON
			var entity domain.ManagementEntity
			if err := json.Unmarshal(data, &entity); err != nil {
				continue // Skip files we can't parse
			}

			entities = append(entities, &entity)
		}
	}

	return entities, nil
}

// Close closes the storage (no-op for file storage)
func (jfs *JSONFileStorage) Close() error {
	return nil
}

// BeginTransaction creates a new transaction (simplified for file storage)
func (jfs *JSONFileStorage) BeginTransaction() (Transaction, error) {
	return &JSONFileTransaction{
		storage: jfs,
		changes: make(map[string]*domain.ManagementEntity),
		deletes: make(map[string]bool),
	}, nil
}

// JSONFileTransaction implements Transaction for JSON file storage
type JSONFileTransaction struct {
	storage    *JSONFileStorage
	mu         sync.Mutex
	changes    map[string]*domain.ManagementEntity
	deletes    map[string]bool
	committed  bool
	rolledback bool
}

// Save stores a ManagementEntity within the transaction
func (tx *JSONFileTransaction) Save(entity *domain.ManagementEntity) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	if entity.ID == "" {
		return fmt.Errorf("entity ID cannot be empty")
	}

	entity.UpdatedAt = time.Now()
	tx.changes[entity.ID] = entity
	delete(tx.deletes, entity.ID) // Remove from deletes if it was marked for deletion

	return nil
}

// FindByID retrieves a ManagementEntity by ID within the transaction
func (tx *JSONFileTransaction) FindByID(id string) (*domain.ManagementEntity, error) {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return nil, fmt.Errorf("transaction is already closed")
	}

	// Check if entity is marked for deletion in this transaction
	if tx.deletes[id] {
		return nil, nil
	}

	// Check if entity is modified in this transaction
	if entity, exists := tx.changes[id]; exists {
		return copyEntity(entity), nil
	}

	// Fall back to storage
	return tx.storage.FindByID(id)
}

// Delete removes a ManagementEntity by ID within the transaction
func (tx *JSONFileTransaction) Delete(id string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	if id == "" {
		return fmt.Errorf("entity ID cannot be empty")
	}

	tx.deletes[id] = true
	delete(tx.changes, id) // Remove from changes if it was modified

	return nil
}

// Commit commits the transaction
func (tx *JSONFileTransaction) Commit() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	// Apply all changes
	for _, entity := range tx.changes {
		if err := tx.storage.Save(entity); err != nil {
			return fmt.Errorf("failed to save entity during commit: %w", err)
		}
	}

	// Apply all deletions
	for id := range tx.deletes {
		if err := tx.storage.Delete(id); err != nil {
			return fmt.Errorf("failed to delete entity during commit: %w", err)
		}
	}

	tx.committed = true
	return nil
}

// Rollback rolls back the transaction
func (tx *JSONFileTransaction) Rollback() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	// Clear all changes
	tx.changes = make(map[string]*domain.ManagementEntity)
	tx.deletes = make(map[string]bool)
	tx.rolledback = true

	return nil
}

// copyEntity creates a deep copy of a ManagementEntity
func copyEntity(original *domain.ManagementEntity) *domain.ManagementEntity {
	if original == nil {
		return nil
	}

	copy := *original

	// Deep copy nested structures
	if original.RequestedPresentation != nil {
		presentation := *original.RequestedPresentation
		copy.RequestedPresentation = &presentation

		// Copy input descriptors slice
		if len(original.RequestedPresentation.InputDescriptors) > 0 {
			copy.RequestedPresentation.InputDescriptors = make([]domain.InputDescriptor, len(original.RequestedPresentation.InputDescriptors))
			for i, desc := range original.RequestedPresentation.InputDescriptors {
				copy.RequestedPresentation.InputDescriptors[i] = desc
			}
		}
	}

	if original.WalletResponse != nil {
		response := *original.WalletResponse
		copy.WalletResponse = &response
	}

	return &copy
}
