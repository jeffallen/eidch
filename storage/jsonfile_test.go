package storage

import (
	"eidch-verifier-agent-oid4vp-go/domain"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJSONFileStorage(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "jsonfile_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create storage
	storage, err := NewJSONFileStorage(tempDir)
	if err != nil {
		t.Fatalf("Failed to create JSONFileStorage: %v", err)
	}
	defer storage.Close()

	// Test Save and FindByID
	entity := &domain.ManagementEntity{
		ID:                             "test-id-1",
		RequestNonce:                   "test-nonce",
		State:                          domain.VerificationStatusPending,
		JWTSecuredAuthorizationRequest: true,
		ExpirationInSeconds:            300,
		CreatedAt:                      time.Now(),
	}

	// Save entity
	err = storage.Save(entity)
	if err != nil {
		t.Fatalf("Failed to save entity: %v", err)
	}

	// Verify file was created
	filepath := filepath.Join(tempDir, "test-id-1.json")
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		t.Fatalf("JSON file was not created")
	}

	// Find by ID
	found, err := storage.FindByID("test-id-1")
	if err != nil {
		t.Fatalf("Failed to find entity: %v", err)
	}

	if found == nil {
		t.Fatalf("Entity not found")
	}

	if found.ID != entity.ID || found.RequestNonce != entity.RequestNonce {
		t.Fatalf("Entity data mismatch")
	}

	// Test Delete
	err = storage.Delete("test-id-1")
	if err != nil {
		t.Fatalf("Failed to delete entity: %v", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(filepath); !os.IsNotExist(err) {
		t.Fatalf("JSON file was not deleted")
	}

	// Verify entity is not found
	found, err = storage.FindByID("test-id-1")
	if err != nil {
		t.Fatalf("Error finding deleted entity: %v", err)
	}
	if found != nil {
		t.Fatalf("Deleted entity was still found")
	}
}

func TestJSONFileStorageTransaction(t *testing.T) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "jsonfile_tx_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create storage
	storage, err := NewJSONFileStorage(tempDir)
	if err != nil {
		t.Fatalf("Failed to create JSONFileStorage: %v", err)
	}
	defer storage.Close()

	// Test transaction commit
	tx, err := storage.BeginTransaction()
	if err != nil {
		t.Fatalf("Failed to begin transaction: %v", err)
	}

	entity := &domain.ManagementEntity{
		ID:                  "tx-test-id",
		RequestNonce:        "tx-test-nonce",
		State:               domain.VerificationStatusPending,
		ExpirationInSeconds: 300,
		CreatedAt:           time.Now(),
	}

	err = tx.Save(entity)
	if err != nil {
		t.Fatalf("Failed to save entity in transaction: %v", err)
	}

	// Entity should not be visible outside transaction yet
	found, err := storage.FindByID("tx-test-id")
	if err != nil {
		t.Fatalf("Error finding entity before commit: %v", err)
	}
	if found != nil {
		t.Fatalf("Entity should not be visible before commit")
	}

	// Commit transaction
	err = tx.Commit()
	if err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	// Entity should now be visible
	found, err = storage.FindByID("tx-test-id")
	if err != nil {
		t.Fatalf("Error finding entity after commit: %v", err)
	}
	if found == nil {
		t.Fatalf("Entity should be visible after commit")
	}

	// Test transaction rollback
	tx2, err := storage.BeginTransaction()
	if err != nil {
		t.Fatalf("Failed to begin second transaction: %v", err)
	}

	entity2 := &domain.ManagementEntity{
		ID:                  "tx-rollback-id",
		RequestNonce:        "rollback-nonce",
		State:               domain.VerificationStatusPending,
		ExpirationInSeconds: 300,
		CreatedAt:           time.Now(),
	}

	err = tx2.Save(entity2)
	if err != nil {
		t.Fatalf("Failed to save entity in second transaction: %v", err)
	}

	// Rollback transaction
	err = tx2.Rollback()
	if err != nil {
		t.Fatalf("Failed to rollback transaction: %v", err)
	}

	// Entity should not be visible after rollback
	found, err = storage.FindByID("tx-rollback-id")
	if err != nil {
		t.Fatalf("Error finding entity after rollback: %v", err)
	}
	if found != nil {
		t.Fatalf("Entity should not be visible after rollback")
	}
}
