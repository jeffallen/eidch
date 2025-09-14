package service

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jeffallen/eiech/config"
	"github.com/jeffallen/eiech/domain"
	"github.com/jeffallen/eiech/storage"
)

// VerificationError represents a verification error with context
type VerificationError struct {
	Type    domain.VerificationError             `json:"error"`
	Code    domain.VerificationErrorResponseCode `json:"error_code"`
	Message string                               `json:"error_description"`
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("%s: %s - %s", e.Type, e.Code, e.Message)
}

// VerificationService handles verification operations
type VerificationService struct {
	config *config.Config
	repo   storage.Repository
}

// NewVerificationService creates a new VerificationService
func NewVerificationService(cfg *config.Config, repo storage.Repository) *VerificationService {
	return &VerificationService{
		config: cfg,
		repo:   repo,
	}
}

// ReceiveVerificationPresentation processes a verification presentation from a wallet
func (s *VerificationService) ReceiveVerificationPresentation(managementEntityID string, request *domain.VerificationPresentationRequest) error {
	log.Printf("Processing verification presentation for entity ID: %s", managementEntityID)

	// Load management entity
	entity, err := s.getManagementEntity(managementEntityID)
	if err != nil {
		return err
	}

	log.Printf("Loaded management entity for %s", managementEntityID)

	// Check if process is still pending and not expired
	if err := s.verifyProcessNotClosed(entity); err != nil {
		s.markVerificationAsFailed(managementEntityID, err)
		return err
	}

	// Handle client rejection
	if request.IsClientRejection() {
		s.markVerificationAsFailedDueToClientRejection(managementEntityID, request.ErrorDescription)
		return nil // Client rejection is handled gracefully
	}

	// Verify the presentation
	log.Printf("Starting submission verification for %s", managementEntityID)
	credentialSubjectData, err := s.verifyPresentation(entity, request)
	if err != nil {
		s.markVerificationAsFailed(managementEntityID, err)
		return err
	}

	log.Printf("Submission verification completed for %s", managementEntityID)

	// Mark as succeeded
	s.markVerificationAsSucceeded(managementEntityID, credentialSubjectData)
	log.Printf("Saved successful verification result for %s", managementEntityID)

	return nil
}

// getManagementEntity retrieves a management entity by ID
func (s *VerificationService) getManagementEntity(id string) (*domain.ManagementEntity, error) {
	entity, err := s.repo.FindByID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to load management entity: %w", err)
	}

	if entity == nil {
		return nil, &VerificationError{
			Type:    domain.VerificationErrorAuthorizationRequestObjectNotFound,
			Code:    domain.CredentialInvalid,
			Message: "Management entity not found",
		}
	}

	return entity, nil
}

// verifyProcessNotClosed checks if the verification process is still open
func (s *VerificationService) verifyProcessNotClosed(entity *domain.ManagementEntity) error {
	if entity.IsExpired() || !entity.IsVerificationPending() {
		return &VerificationError{
			Type:    domain.VerificationErrorVerificationProcessClosed,
			Code:    domain.CredentialInvalid,
			Message: "Verification process is closed or expired",
		}
	}
	return nil
}

// verifyPresentation verifies the VP token and presentation submission
func (s *VerificationService) verifyPresentation(entity *domain.ManagementEntity, request *domain.VerificationPresentationRequest) (string, error) {
	// Parse and validate presentation submission
	presentationSubmission, err := s.parseAndValidatePresentationSubmission(request.PresentationSubmission)
	if err != nil {
		return "", err
	}

	// Check required parameters
	if strings.TrimSpace(request.VPToken) == "" || presentationSubmission == nil {
		return "", &VerificationError{
			Type:    domain.VerificationErrorAuthorizationRequestMissingParam,
			Code:    domain.CredentialInvalid,
			Message: "Missing required parameters: vp_token or presentation_submission",
		}
	}

	log.Printf("Successfully verified presentation submission for id %s", entity.ID)

	// Verify the credential based on format
	return s.verifyCredential(entity, request.VPToken, presentationSubmission)
}

// parseAndValidatePresentationSubmission parses the presentation submission JSON
func (s *VerificationService) parseAndValidatePresentationSubmission(submissionJSON string) (*domain.PresentationSubmission, error) {
	if strings.TrimSpace(submissionJSON) == "" {
		return nil, &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidPresentationSubmission,
			Message: "Presentation submission is empty",
		}
	}

	var submission domain.PresentationSubmission
	if err := json.Unmarshal([]byte(submissionJSON), &submission); err != nil {
		return nil, &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidPresentationSubmission,
			Message: fmt.Sprintf("Invalid presentation submission JSON: %v", err),
		}
	}

	// Basic validation
	if submission.ID == "" {
		return nil, &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidPresentationSubmission,
			Message: "Presentation submission missing ID",
		}
	}

	if len(submission.DescriptorMap) == 0 {
		return nil, &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidPresentationSubmission,
			Message: "Presentation submission missing descriptor map",
		}
	}

	return &submission, nil
}

// verifyCredential verifies the credential based on its format
func (s *VerificationService) verifyCredential(entity *domain.ManagementEntity, vpToken string, submission *domain.PresentationSubmission) (string, error) {
	if len(submission.DescriptorMap) == 0 {
		return "", &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidFormat,
			Message: "No descriptor map found in presentation submission",
		}
	}

	format := submission.DescriptorMap[0].Format
	if format == "" {
		return "", &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.UnsupportedFormat,
			Message: "Format not specified in descriptor map",
		}
	}

	switch format {
	case "vc+sd-jwt":
		return s.verifySdJwtCredential(entity, vpToken, submission)
	default:
		return "", &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.UnsupportedFormat,
			Message: fmt.Sprintf("Unsupported credential format: %s", format),
		}
	}
}

// verifySdJwtCredential verifies an SD-JWT credential (simplified implementation)
func (s *VerificationService) verifySdJwtCredential(entity *domain.ManagementEntity, vpToken string, submission *domain.PresentationSubmission) (string, error) {
	log.Printf("Verifying SD-JWT credential for entity %s", entity.ID)

	// This is a simplified implementation
	// In a real implementation, we would:
	// 1. Parse the SD-JWT token
	// 2. Verify the JWT signature using the issuer's public key
	// 3. Check credential status (revocation, expiration)
	// 4. Validate against the presentation definition requirements
	// 5. Extract and return the credential subject data

	// For this demo, we'll do basic JWT parsing and return mock data
	parts := strings.Split(vpToken, ".")
	if len(parts) < 2 {
		return "", &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.InvalidFormat,
			Message: "Invalid JWT format in VP token",
		}
	}

	// Basic validation - check if it looks like a valid JWT structure
	if !s.isValidJWTStructure(vpToken) {
		return "", &VerificationError{
			Type:    domain.VerificationErrorInvalidPresentationDefinition,
			Code:    domain.CredentialInvalid,
			Message: "Invalid credential structure",
		}
	}

	// For this simplified implementation, return success with mock credential subject data
	credentialSubjectData := fmt.Sprintf(`{
		"verified_at": "%s",
		"credential_format": "vc+sd-jwt",
		"presentation_definition_id": "%s",
		"status": "verified"
	}`, time.Now().Format(time.RFC3339), submission.DefinitionID)

	log.Printf("Successfully verified SD-JWT credential for entity %s", entity.ID)
	return credentialSubjectData, nil
}

// isValidJWTStructure performs basic JWT structure validation
func (s *VerificationService) isValidJWTStructure(token string) bool {
	parts := strings.Split(token, ".")
	return len(parts) >= 2 // At minimum header.payload (SD-JWT might not have signature)
}

// markVerificationAsSucceeded marks the verification as successful
func (s *VerificationService) markVerificationAsSucceeded(managementEntityID, credentialSubjectData string) {
	entity, err := s.repo.FindByID(managementEntityID)
	if err != nil {
		log.Printf("Failed to load entity for success marking: %v", err)
		return
	}
	if entity != nil {
		entity.VerificationSucceeded(credentialSubjectData)
		if err := s.repo.Save(entity); err != nil {
			log.Printf("Failed to save successful verification result: %v", err)
		}
	}
}

// markVerificationAsFailed marks the verification as failed
func (s *VerificationService) markVerificationAsFailed(managementEntityID string, verErr error) {
	entity, err := s.repo.FindByID(managementEntityID)
	if err != nil {
		log.Printf("Failed to load entity for failure marking: %v", err)
		return
	}
	if entity != nil {
		if ve, ok := verErr.(*VerificationError); ok {
			entity.VerificationFailed(ve.Type, ve.Code)
		} else {
			entity.VerificationFailed(domain.VerificationErrorInvalidRequest, domain.CredentialInvalid)
		}
		if err := s.repo.Save(entity); err != nil {
			log.Printf("Failed to save failed verification result: %v", err)
		}
	}
}

// markVerificationAsFailedDueToClientRejection marks verification as failed due to client rejection
func (s *VerificationService) markVerificationAsFailedDueToClientRejection(managementEntityID, errorDescription string) {
	entity, err := s.repo.FindByID(managementEntityID)
	if err != nil {
		log.Printf("Failed to load entity for client rejection marking: %v", err)
		return
	}
	if entity != nil {
		entity.VerificationFailedDueToClientRejection(errorDescription)
		if err := s.repo.Save(entity); err != nil {
			log.Printf("Failed to save client rejection result: %v", err)
		}
	}
}
