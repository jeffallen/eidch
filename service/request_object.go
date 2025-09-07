package service

import (
	"eidch-verifier-agent-oid4vp-go/config"
	"eidch-verifier-agent-oid4vp-go/domain"
	"eidch-verifier-agent-oid4vp-go/jwt"
	"eidch-verifier-agent-oid4vp-go/storage"
	"fmt"
	"log"
)

// RequestObjectService handles request object operations
type RequestObjectService struct {
	config *config.Config
	repo   storage.Repository
	signer jwt.Signer
}

// NewRequestObjectService creates a new RequestObjectService
func NewRequestObjectService(cfg *config.Config, repo storage.Repository) *RequestObjectService {
	service := &RequestObjectService{
		config: cfg,
		repo:   repo,
	}

	// Initialize signer if private key is configured
	if cfg.Signing.PrivateKeyPEM != "" {
		signer, err := jwt.NewES256Signer(cfg.Signing.PrivateKeyPEM, cfg.Signing.KeyID)
		if err != nil {
			log.Printf("Failed to initialize JWT signer: %v", err)
		} else {
			service.signer = signer
		}
	}

	return service
}

// AssembleRequestObject creates a request object for the given management entity ID
func (s *RequestObjectService) AssembleRequestObject(managementEntityID string) (interface{}, error) {
	log.Printf("Prepare request object for mgmt-id %s", managementEntityID)

	// Load management entity
	entity, err := s.repo.FindByID(managementEntityID)
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

	// Check if verification is still pending
	if !entity.IsVerificationPending() {
		log.Printf("ManagementEntity with id %s is requested after already processing it", managementEntityID)
		return nil, &VerificationError{
			Type:    domain.VerificationErrorVerificationProcessClosed,
			Code:    domain.CredentialInvalid,
			Message: "Verification process is closed",
		}
	}

	// Check if expired
	if entity.IsExpired() {
		log.Printf("ManagementEntity with id %s is expired", managementEntityID)
		return nil, &VerificationError{
			Type:    domain.VerificationErrorAuthorizationRequestObjectNotFound,
			Code:    domain.CredentialInvalid,
			Message: "Verification process has expired",
		}
	}

	// Create request object
	requestObject := &domain.RequestObject{
		Nonce:                  entity.RequestNonce,
		Version:                s.config.RequestObjectVersion,
		PresentationDefinition: entity.RequestedPresentation,
		ClientID:               s.config.ClientID,
		ClientMetadata:         s.config.Client.Metadata,
		ClientIDScheme:         s.config.ClientIDScheme,
		ResponseType:           "vp_token",
		ResponseMode:           "direct_post",
		ResponseURI: fmt.Sprintf("%s/api/v1/request-object/%s/response-data",
			s.config.ExternalURL, managementEntityID),
	}

	// If JWT secured authorization is not required, return request object as-is
	if !entity.JWTSecuredAuthorizationRequest {
		return requestObject, nil
	}

	// Check if signer is available
	if s.signer == nil {
		log.Println("ERROR: Upstream system requested presentation to be signed but no signing key was configured")
		return nil, fmt.Errorf("presentation was configured to be signed, but no signing key was configured")
	}

	// Create JWT claims from request object
	claims := &jwt.Claims{
		Issuer: s.config.ClientID,
		Extra:  s.requestObjectToMap(requestObject),
	}

	// Sign and return JWT
	signedJWT, err := jwt.CreateToken(claims, s.signer)
	if err != nil {
		return nil, fmt.Errorf("error signing JWT: %w", err)
	}

	return signedJWT, nil
}

// requestObjectToMap converts a request object to a map for JWT claims
func (s *RequestObjectService) requestObjectToMap(obj *domain.RequestObject) map[string]interface{} {
	result := make(map[string]interface{})

	if obj.Nonce != "" {
		result["nonce"] = obj.Nonce
	}
	if obj.Version != "" {
		result["version"] = obj.Version
	}
	if obj.PresentationDefinition != nil {
		result["presentation_definition"] = obj.PresentationDefinition
	}
	if obj.ClientID != "" {
		result["client_id"] = obj.ClientID
	}
	if obj.ClientMetadata != nil {
		result["client_metadata"] = obj.ClientMetadata
	}
	if obj.ClientIDScheme != "" {
		result["client_id_scheme"] = obj.ClientIDScheme
	}
	if obj.ResponseType != "" {
		result["response_type"] = obj.ResponseType
	}
	if obj.ResponseMode != "" {
		result["response_mode"] = obj.ResponseMode
	}
	if obj.ResponseURI != "" {
		result["response_uri"] = obj.ResponseURI
	}

	return result
}
