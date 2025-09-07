package service

import (
	"eidch-verifier-agent-oid4vp-go/config"
	"eidch-verifier-agent-oid4vp-go/domain"
	"eidch-verifier-agent-oid4vp-go/storage"
	"testing"
	"time"
)

func TestVerificationService_ReceiveVerificationPresentation(t *testing.T) {
	// Create test config
	cfg := &config.Config{
		ClientID: "test-client-id",
	}

	// Create memory storage
	repo, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("Failed to create memory storage: %v", err)
	}

	// Create verification service
	service := NewVerificationService(cfg, repo)

	// Create test entity
	entity := &domain.ManagementEntity{
		ID:                             "test-entity-id",
		RequestNonce:                   "test-nonce",
		State:                          domain.VerificationStatusPending,
		JWTSecuredAuthorizationRequest: false,
		ExpirationInSeconds:            300,
		CreatedAt:                      time.Now(),
		RequestedPresentation: &domain.PresentationDefinition{
			ID:   "test-def-id",
			Name: "Test Definition",
		},
	}

	// Save entity
	err = repo.Save(entity)
	if err != nil {
		t.Fatalf("Failed to save test entity: %v", err)
	}

	// Test successful verification
	request := &domain.VerificationPresentationRequest{
		VPToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		PresentationSubmission: `{
			"id": "test-submission-id",
			"definition_id": "test-def-id",
			"descriptor_map": [
				{
					"id": "test-descriptor",
					"format": "vc+sd-jwt",
					"path": "$"
				}
			]
		}`,
	}

	err = service.ReceiveVerificationPresentation("test-entity-id", request)
	if err != nil {
		t.Fatalf("Verification should have succeeded: %v", err)
	}

	// Check that entity was updated
	updated, err := repo.FindByID("test-entity-id")
	if err != nil {
		t.Fatalf("Failed to find updated entity: %v", err)
	}

	if updated.State != domain.VerificationStatusSucceeded {
		t.Fatalf("Expected status SUCCEEDED, got %s", updated.State)
	}

	if updated.WalletResponse == nil || updated.WalletResponse.CredentialSubjectData == "" {
		t.Fatalf("Expected credential subject data to be set")
	}
}

func TestVerificationService_ClientRejection(t *testing.T) {
	// Create test config
	cfg := &config.Config{
		ClientID: "test-client-id",
	}

	// Create memory storage
	repo, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("Failed to create memory storage: %v", err)
	}

	// Create verification service
	service := NewVerificationService(cfg, repo)

	// Create test entity
	entity := &domain.ManagementEntity{
		ID:                             "test-rejection-id",
		RequestNonce:                   "test-nonce",
		State:                          domain.VerificationStatusPending,
		JWTSecuredAuthorizationRequest: false,
		ExpirationInSeconds:            300,
		CreatedAt:                      time.Now(),
	}

	// Save entity
	err = repo.Save(entity)
	if err != nil {
		t.Fatalf("Failed to save test entity: %v", err)
	}

	// Test client rejection
	request := &domain.VerificationPresentationRequest{
		Error:            "access_denied",
		ErrorDescription: "User cancelled the request",
	}

	err = service.ReceiveVerificationPresentation("test-rejection-id", request)
	if err != nil {
		t.Fatalf("Client rejection should not return error: %v", err)
	}

	// Check that entity was updated with failure
	updated, err := repo.FindByID("test-rejection-id")
	if err != nil {
		t.Fatalf("Failed to find updated entity: %v", err)
	}

	if updated.State != domain.VerificationStatusFailed {
		t.Fatalf("Expected status FAILED, got %s", updated.State)
	}

	if updated.WalletResponse == nil || updated.WalletResponse.ErrorCode != string(domain.ClientRejected) {
		t.Fatalf("Expected CLIENT_REJECTED error code")
	}
}

func TestVerificationService_ExpiredEntity(t *testing.T) {
	// Create test config
	cfg := &config.Config{
		ClientID: "test-client-id",
	}

	// Create memory storage
	repo, err := storage.NewMemoryStorage()
	if err != nil {
		t.Fatalf("Failed to create memory storage: %v", err)
	}

	// Create verification service
	service := NewVerificationService(cfg, repo)

	// Create expired test entity
	entity := &domain.ManagementEntity{
		ID:                             "test-expired-id",
		RequestNonce:                   "test-nonce",
		State:                          domain.VerificationStatusPending,
		JWTSecuredAuthorizationRequest: false,
		ExpirationInSeconds:            1,                                // 1 second expiration
		CreatedAt:                      time.Now().Add(-2 * time.Second), // 2 seconds ago
	}

	// Save entity
	err = repo.Save(entity)
	if err != nil {
		t.Fatalf("Failed to save test entity: %v", err)
	}

	// Test with expired entity
	request := &domain.VerificationPresentationRequest{
		VPToken:                "test-token",
		PresentationSubmission: `{"id": "test", "definition_id": "test", "descriptor_map": []}`,
	}

	err = service.ReceiveVerificationPresentation("test-expired-id", request)
	if err == nil {
		t.Fatalf("Expected error for expired entity")
	}

	if verErr, ok := err.(*VerificationError); !ok || verErr.Type != domain.VerificationErrorVerificationProcessClosed {
		t.Fatalf("Expected VERIFICATION_PROCESS_CLOSED error, got %v", err)
	}
}
