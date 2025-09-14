package storage

import (
	"fmt"
	"sync"
	"time"

	"github.com/jeffallen/eiech/domain"
)

// MemoryStorage implements an in-memory storage for ManagementEntity
type MemoryStorage struct {
	mu       sync.RWMutex
	entities map[string]*domain.ManagementEntity
}

// NewMemoryStorage creates a new in-memory storage instance
func NewMemoryStorage() (*MemoryStorage, error) {
	return &MemoryStorage{
		entities: make(map[string]*domain.ManagementEntity),
	}, nil
}

// Save stores a ManagementEntity
func (ms *MemoryStorage) Save(entity *domain.ManagementEntity) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	entity.UpdatedAt = time.Now()
	ms.entities[entity.ID] = entity
	return nil
}

// FindByID retrieves a ManagementEntity by ID
func (ms *MemoryStorage) FindByID(id string) (*domain.ManagementEntity, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	entity, exists := ms.entities[id]
	if !exists {
		return nil, nil // Not found, but not an error
	}

	// Return a copy to avoid concurrent modification issues
	return copyEntityMemory(entity), nil
}

// Delete removes a ManagementEntity by ID
func (ms *MemoryStorage) Delete(id string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	delete(ms.entities, id)
	return nil
}

// List returns all ManagementEntities (for testing/debugging)
func (ms *MemoryStorage) List() ([]*domain.ManagementEntity, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	result := make([]*domain.ManagementEntity, 0, len(ms.entities))
	for _, entity := range ms.entities {
		result = append(result, copyEntityMemory(entity))
	}
	return result, nil
}

// CleanupExpired removes expired entities
func (ms *MemoryStorage) CleanupExpired() error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	for id, entity := range ms.entities {
		if entity.IsExpired() {
			delete(ms.entities, id)
		}
	}
	return nil
}

// copyEntityMemory creates a deep copy of a ManagementEntity to avoid concurrent modification
func copyEntityMemory(original *domain.ManagementEntity) *domain.ManagementEntity {
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
				// Note: This is a shallow copy of nested maps/slices
				// For a complete deep copy, we'd need to copy Format, Constraints, etc.
			}
		}
	}

	if original.WalletResponse != nil {
		response := *original.WalletResponse
		copy.WalletResponse = &response
	}

	return &copy
}

// Close closes the storage (no-op for memory storage)
func (ms *MemoryStorage) Close() error {
	return nil
}

// BeginTransaction creates a new transaction (simplified for memory storage)
func (ms *MemoryStorage) BeginTransaction() (Transaction, error) {
	return &MemoryTransaction{
		storage: ms,
		changes: make(map[string]*domain.ManagementEntity),
		deletes: make(map[string]bool),
	}, nil
}

// MemoryTransaction implements Transaction for memory storage
type MemoryTransaction struct {
	storage    *MemoryStorage
	mu         sync.Mutex
	changes    map[string]*domain.ManagementEntity
	deletes    map[string]bool
	committed  bool
	rolledback bool
}

// Save stores a ManagementEntity within the transaction
func (tx *MemoryTransaction) Save(entity *domain.ManagementEntity) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	entity.UpdatedAt = time.Now()
	tx.changes[entity.ID] = copyEntityMemory(entity)
	delete(tx.deletes, entity.ID) // Remove from deletes if it was marked for deletion

	return nil
}

// FindByID retrieves a ManagementEntity by ID within the transaction
func (tx *MemoryTransaction) FindByID(id string) (*domain.ManagementEntity, error) {
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
		return copyEntityMemory(entity), nil
	}

	// Fall back to storage
	return tx.storage.FindByID(id)
}

// Delete removes a ManagementEntity by ID within the transaction
func (tx *MemoryTransaction) Delete(id string) error {
	tx.mu.Lock()
	defer tx.mu.Unlock()

	if tx.committed || tx.rolledback {
		return fmt.Errorf("transaction is already closed")
	}

	tx.deletes[id] = true
	delete(tx.changes, id) // Remove from changes if it was modified

	return nil
}

// Commit commits the transaction
func (tx *MemoryTransaction) Commit() error {
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
func (tx *MemoryTransaction) Rollback() error {
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
