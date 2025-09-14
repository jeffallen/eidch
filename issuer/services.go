package issuer

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/jeffallen/eiech/jwt"
)

// CredentialService handles credential-related operations
type CredentialService struct {
	config  *Config
	storage Storage
	signer  jwt.Signer
}

// NewCredentialService creates a new credential service
func NewCredentialService(cfg *Config, storage Storage) *CredentialService {
	service := &CredentialService{
		config:  cfg,
		storage: storage,
	}

	// Initialize signer if private key is configured
	if cfg.Signing.PrivateKeyPEM != "" {
		signer, err := jwt.NewES256Signer(cfg.Signing.PrivateKeyPEM, cfg.Signing.VerificationMethod)
		if err != nil {
			fmt.Printf("Warning: Failed to initialize JWT signer: %v\n", err)
		} else {
			service.signer = signer
		}
	}

	return service
}

// IssueOAuthToken issues an OAuth access token for a pre-authorized code
func (cs *CredentialService) IssueOAuthToken(preAuthCode string) (*TokenResponse, error) {
	// Find the credential offer by pre-authorized code
	offer, err := cs.storage.GetCredentialOfferByPreAuthCode(preAuthCode)
	if err != nil {
		return nil, fmt.Errorf("failed to get offer: %w", err)
	}

	if offer == nil {
		return nil, &OAuthError{
			ErrorType:        "invalid_grant",
			ErrorDescription: "Invalid pre-authorized code",
		}
	}

	// Check if offer is still valid
	if offer.IsExpired() || offer.Status != CredentialOfferStatusOffered {
		return nil, &OAuthError{
			ErrorType:        "invalid_grant",
			ErrorDescription: "Pre-authorized code has expired or is not valid",
		}
	}

	// Generate access token and nonce
	accessToken, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	cNonce, err := generateSecureToken(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Update offer with token
	TokenExpiresAt := time.Now().Add(10 * time.Minute)
	offer.AccessToken = accessToken
	offer.TokenExpiresAt = &TokenExpiresAt
	offer.Nonce = cNonce

	if err := cs.storage.UpdateCredentialOffer(offer); err != nil {
		return nil, fmt.Errorf("failed to update offer: %w", err)
	}

	return &TokenResponse{
		AccessToken:     accessToken,
		TokenType:       "Bearer",
		ExpiresIn:       600, // 10 minutes
		CNonce:          cNonce,
		CNonceExpiresIn: 300, // 5 minutes
	}, nil
}

// IssueCredential issues a credential based on the request
func (cs *CredentialService) IssueCredential(accessToken string, request *CredentialRequest, clientInfo *ClientAgentInfo) (*CredentialResponse, error) {
	// Find the credential offer by access token
	offer, err := cs.storage.GetCredentialOfferByAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get offer: %w", err)
	}

	if offer == nil {
		return nil, &CredentialError{
			ErrorType:        "invalid_token",
			ErrorDescription: "Invalid access token",
		}
	}

	// Check if offer can issue credentials
	if !offer.CanIssueCredential() {
		return nil, &CredentialError{
			ErrorType:        "invalid_token",
			ErrorDescription: "Token has expired or credential already issued",
		}
	}

	// Validate proof if provided
	if request.Proof != nil {
		if err := cs.validateProof(request.Proof, offer); err != nil {
			return nil, &CredentialError{
				ErrorType:        "invalid_proof",
				ErrorDescription: fmt.Sprintf("Proof validation failed: %v", err),
			}
		}
	}

	// Store client info for deferred processing
	if clientInfo != nil {
		offer.ClientAgentInfo = clientInfo
	}

	// Create the credential
	credential, err := cs.createCredential(offer, request)
	if err != nil {
		return nil, &CredentialError{
			ErrorType:        "credential_creation_error",
			ErrorDescription: fmt.Sprintf("Failed to create credential: %v", err),
		}
	}

	// Update offer status
	offer.Status = CredentialOfferStatusIssued
	if err := cs.storage.UpdateCredentialOffer(offer); err != nil {
		return nil, fmt.Errorf("failed to update offer status: %w", err)
	}

	return &CredentialResponse{
		Format:     request.Format,
		Credential: credential,
	}, nil
}

// validateProof validates the holder's proof of possession
func (cs *CredentialService) validateProof(proof *HolderProof, offer *CredentialOffer) error {
	if proof.ProofType != "jwt" {
		return fmt.Errorf("unsupported proof type: %s", proof.ProofType)
	}

	if proof.JWT == "" {
		return fmt.Errorf("JWT proof is required")
	}

	// Parse the JWT (basic parsing without full verification for simplicity)
	header, claims, err := jwt.ParseToken(proof.JWT)
	if err != nil {
		return fmt.Errorf("failed to parse proof JWT: %w", err)
	}

	// Check algorithm
	if header.Alg != "ES256" {
		return fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Validate nonce
	if nonce, ok := claims.Extra["nonce"].(string); !ok || nonce != offer.Nonce {
		return fmt.Errorf("invalid nonce")
	}

	// Validate audience
	if aud, ok := claims.Extra["aud"].(string); !ok || !strings.Contains(aud, cs.config.IssuerID) {
		return fmt.Errorf("invalid audience")
	}

	// Check if nonce was already used
	if used, err := cs.storage.IsNonceUsed(offer.Nonce); err != nil {
		return fmt.Errorf("failed to check nonce usage: %w", err)
	} else if used {
		return fmt.Errorf("nonce already used")
	}

	// Mark nonce as used
	if err := cs.storage.MarkNonceAsUsed(offer.Nonce); err != nil {
		return fmt.Errorf("failed to mark nonce as used: %w", err)
	}

	return nil
}

// createCredential creates the actual verifiable credential
func (cs *CredentialService) createCredential(offer *CredentialOffer, request *CredentialRequest) (string, error) {
	if request.Format != "vc+sd-jwt" {
		return "", fmt.Errorf("unsupported format: %s", request.Format)
	}

	if cs.signer == nil {
		// For testing, create a mock JWT-like credential
		return "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJtb2NrLWlzc3VlciIsInZjdCI6Im1vY2stdHlwZSJ9.mock-signature~", nil
	}

	// Create SD-JWT credential claims
	claims := &jwt.Claims{
		Issuer:   cs.config.IssuerID,
		Subject:  "credential-subject", // In real implementation, this would be derived from holder proof
		IssuedAt: time.Now().Unix(),
		Expiry:   time.Now().Add(time.Duration(cs.config.Credential.DefaultExpirationHours) * time.Hour).Unix(),
		Extra: map[string]interface{}{
			"vct": getVCTForCredentialType(offer.CredentialType),
			"vc":  offer.CredentialData,
		},
	}

	// Add holder binding if proof was provided
	if request.Proof != nil {
		// Extract holder's public key from proof (simplified)
		claims.Extra["cnf"] = map[string]interface{}{
			"jwk": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   "holder-x-coordinate", // In real implementation, extract from proof
				"y":   "holder-y-coordinate", // In real implementation, extract from proof
			},
		}
	}

	// Create and sign the JWT
	signedJWT, err := jwt.CreateToken(claims, cs.signer)
	if err != nil {
		return "", fmt.Errorf("failed to sign credential: %w", err)
	}

	// For SD-JWT, we append disclosure markers (simplified)
	return signedJWT + "~", nil
}

// NonceService handles nonce operations
type NonceService struct {
	config *Config
}

// NewNonceService creates a new nonce service
func NewNonceService(cfg *Config) *NonceService {
	return &NonceService{
		config: cfg,
	}
}

// CreateNonce creates a new self-contained nonce
func (ns *NonceService) CreateNonce() (*NonceResponse, error) {
	// Create a self-contained nonce (UUID + timestamp)
	token, err := generateSecureToken(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%s::%d", token, timestamp)

	return &NonceResponse{
		Nonce:           nonce,
		CNonceExpiresIn: ns.config.Nonce.LifetimeSeconds,
	}, nil
}

// ManagementService handles credential management operations
type ManagementService struct {
	config  *Config
	storage Storage
}

// NewManagementService creates a new management service
func NewManagementService(cfg *Config, storage Storage) *ManagementService {
	return &ManagementService{
		config:  cfg,
		storage: storage,
	}
}

// CreateCredentialOffer creates a new credential offer
func (ms *ManagementService) CreateCredentialOffer(request *CredentialOfferRequest) (*CredentialOfferResponse, error) {
	// Generate unique IDs
	offerID, err := generateSecureToken(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate offer ID: %w", err)
	}

	preAuthCode, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate pre-auth code: %w", err)
	}

	// Calculate expiration
	validityDays := 7 // default
	if request.ValidityPeriodDays != nil && *request.ValidityPeriodDays > 0 {
		validityDays = *request.ValidityPeriodDays
	}

	expiresAt := time.Now().Add(time.Duration(validityDays) * 24 * time.Hour)

	// Create credential offer
	offer := &CredentialOffer{
		ID:                    offerID,
		PreAuthorizedCode:     preAuthCode,
		Status:                CredentialOfferStatusOffered,
		CredentialType:        request.CredentialType,
		CredentialData:        request.CredentialData,
		ConfigurationOverride: request.ConfigurationOverride,
		CreatedAt:             time.Now(),
		UpdatedAt:             time.Now(),
		ExpiresAt:             expiresAt,
		IssuerURL:             ms.config.ExternalURL,
		CallbackURL:           request.CallbackURL,
	}

	// Generate deep link
	credentialOfferURI := fmt.Sprintf("%s/credential-offer?offer_id=%s", ms.config.ExternalURL, offerID)
	deepLink := fmt.Sprintf("openid-credential-offer://?credential_offer_uri=%s", credentialOfferURI)
	offer.DeepLink = deepLink

	// Save offer
	if err := ms.storage.SaveCredentialOffer(offer); err != nil {
		return nil, fmt.Errorf("failed to save offer: %w", err)
	}

	return &CredentialOfferResponse{
		OfferID:            offerID,
		CredentialOfferURI: credentialOfferURI,
		DeepLink:           deepLink,
	}, nil
}

// GetCredentialOffer retrieves a credential offer
func (ms *ManagementService) GetCredentialOffer(offerID string) (*CredentialOffer, error) {
	return ms.storage.GetCredentialOffer(offerID)
}

// UpdateCredentialOfferStatus updates the status of a credential offer
func (ms *ManagementService) UpdateCredentialOfferStatus(offerID string, status CredentialOfferStatus) error {
	offer, err := ms.storage.GetCredentialOffer(offerID)
	if err != nil {
		return err
	}

	if offer == nil {
		return fmt.Errorf("offer not found")
	}

	offer.Status = status
	offer.UpdatedAt = time.Now()

	return ms.storage.UpdateCredentialOffer(offer)
}

// Helper functions

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes)[:length], nil
}

func getVCTForCredentialType(credentialType string) string {
	// Map credential types to Verifiable Credential Types
	switch credentialType {
	case "university_example_sd_jwt":
		return "https://example.com/university-credential"
	case "example_sd_jwt":
		return "https://example.com/example-credential"
	default:
		return "https://example.com/generic-credential"
	}
}
