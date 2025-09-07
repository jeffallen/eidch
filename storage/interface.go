package storage

import "eidch-verifier-agent-oid4vp-go/domain"

// Repository defines the interface for storing and retrieving ManagementEntity objects
type Repository interface {
	// Save stores a ManagementEntity
	Save(entity *domain.ManagementEntity) error

	// FindByID retrieves a ManagementEntity by ID
	FindByID(id string) (*domain.ManagementEntity, error)

	// Delete removes a ManagementEntity by ID
	Delete(id string) error

	// CleanupExpired removes expired entities
	CleanupExpired() error

	// Close closes the storage connection if applicable
	Close() error
}

// WriteRepository defines the interface for write operations with transactional support
type WriteRepository interface {
	Repository

	// BeginTransaction starts a new transaction (if supported)
	BeginTransaction() (Transaction, error)
}

// Transaction defines the interface for database transactions
type Transaction interface {
	// Save stores a ManagementEntity within the transaction
	Save(entity *domain.ManagementEntity) error

	// FindByID retrieves a ManagementEntity by ID within the transaction
	FindByID(id string) (*domain.ManagementEntity, error)

	// Delete removes a ManagementEntity by ID within the transaction
	Delete(id string) error

	// Commit commits the transaction
	Commit() error

	// Rollback rolls back the transaction
	Rollback() error
}
