package issuer

import (
	"time"
)

// CredentialOfferStatus represents the status of a credential offer
type CredentialOfferStatus string

const (
	CredentialOfferStatusOffered   CredentialOfferStatus = "OFFERED"
	CredentialOfferStatusIssued    CredentialOfferStatus = "ISSUED"
	CredentialOfferStatusExpired   CredentialOfferStatus = "EXPIRED"
	CredentialOfferStatusRevoked   CredentialOfferStatus = "REVOKED"
	CredentialOfferStatusSuspended CredentialOfferStatus = "SUSPENDED"
)

// CredentialOffer represents a credential offer
type CredentialOffer struct {
	ID                    string                 `json:"id"`
	PreAuthorizedCode     string                 `json:"pre_authorized_code"`
	AccessToken           string                 `json:"access_token,omitempty"`
	TokenExpiresAt        *time.Time             `json:"token_expires_at,omitempty"`
	Nonce                 string                 `json:"nonce,omitempty"`
	Status                CredentialOfferStatus  `json:"status"`
	CredentialType        string                 `json:"credential_type"`
	CredentialData        map[string]interface{} `json:"credential_data"`
	ConfigurationOverride *ConfigurationOverride `json:"configuration_override,omitempty"`
	CreatedAt             time.Time              `json:"created_at"`
	UpdatedAt             time.Time              `json:"updated_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
	IssuerURL             string                 `json:"issuer_url"`
	DeepLink              string                 `json:"deep_link"`
	CallbackURL           string                 `json:"callback_url,omitempty"`
	ClientAgentInfo       *ClientAgentInfo       `json:"client_agent_info,omitempty"`
}

// ConfigurationOverride allows overriding issuer configuration per credential
type ConfigurationOverride struct {
	IssuerID           *string `json:"issuer_id,omitempty"`
	VerificationMethod *string `json:"verification_method,omitempty"`
	SigningKey         *string `json:"signing_key,omitempty"`
	Metadata           *string `json:"metadata,omitempty"`
}

// ClientAgentInfo holds information about the client agent
type ClientAgentInfo struct {
	RemoteAddr     string `json:"remote_addr,omitempty"`
	UserAgent      string `json:"user_agent,omitempty"`
	AcceptLanguage string `json:"accept_language,omitempty"`
	AcceptEncoding string `json:"accept_encoding,omitempty"`
}

// IsExpired checks if the credential offer has expired
func (co *CredentialOffer) IsExpired() bool {
	return time.Now().After(co.ExpiresAt)
}

// IsTokenExpired checks if the access token has expired
func (co *CredentialOffer) IsTokenExpired() bool {
	if co.TokenExpiresAt == nil {
		return false
	}
	return time.Now().After(*co.TokenExpiresAt)
}

// CanIssueCredential checks if the offer can be used to issue credentials
func (co *CredentialOffer) CanIssueCredential() bool {
	return co.Status == CredentialOfferStatusOffered && !co.IsExpired() && co.AccessToken != "" && !co.IsTokenExpired()
}

// CredentialRequest represents a request for a credential
type CredentialRequest struct {
	Format                       string                        `json:"format"`
	CredentialDefinition         *CredentialDefinition         `json:"credential_definition,omitempty"`
	Proof                        *HolderProof                  `json:"proof,omitempty"`
	CredentialResponseEncryption *CredentialResponseEncryption `json:"credential_response_encryption,omitempty"`
}

// HolderProof represents proof of possession from the credential holder
type HolderProof struct {
	ProofType string `json:"proof_type"`
	JWT       string `json:"jwt,omitempty"`
}

// CredentialResponseEncryption specifies how to encrypt the credential response
type CredentialResponseEncryption struct {
	Algorithm        string                 `json:"alg"`
	EncryptionMethod string                 `json:"enc"`
	JWK              map[string]interface{} `json:"jwk"`
}

// CredentialResponse represents a credential issuance response
type CredentialResponse struct {
	Format          string `json:"format,omitempty"`
	Credential      string `json:"credential,omitempty"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// DeferredCredentialResponse represents a deferred credential response
type DeferredCredentialResponse struct {
	TransactionID   string `json:"transaction_id"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// TokenRequest represents an OAuth token request
type TokenRequest struct {
	GrantType         string `json:"grant_type"`
	PreAuthorizedCode string `json:"pre-authorized_code"`
}

// TokenResponse represents an OAuth token response
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	CNonce          string `json:"c_nonce,omitempty"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in,omitempty"`
}

// NonceResponse represents a nonce response
type NonceResponse struct {
	Nonce           string `json:"nonce"`
	CNonceExpiresIn int    `json:"c_nonce_expires_in"`
}

// CredentialOfferRequest represents a request to create a credential offer
type CredentialOfferRequest struct {
	CredentialType        string                 `json:"credential_type"`
	CredentialData        map[string]interface{} `json:"credential_data"`
	ValidityPeriodDays    *int                   `json:"validity_period_days,omitempty"`
	CallbackURL           string                 `json:"callback_url,omitempty"`
	ConfigurationOverride *ConfigurationOverride `json:"configuration_override,omitempty"`
}

// CredentialOfferResponse represents the response to a credential offer creation
type CredentialOfferResponse struct {
	OfferID            string `json:"offer_id"`
	CredentialOfferURI string `json:"credential_offer_uri"`
	DeepLink           string `json:"deep_link"`
	QRCodeURL          string `json:"qr_code_url,omitempty"`
}

// IssuerMetadata represents the issuer's metadata
type IssuerMetadata struct {
	CredentialIssuer                               string                `json:"credential_issuer"`
	CredentialEndpoint                             string                `json:"credential_endpoint"`
	DeferredCredentialEndpoint                     string                `json:"deferred_credential_endpoint,omitempty"`
	NotificationEndpoint                           string                `json:"notification_endpoint,omitempty"`
	CredentialResponseEncryptionAlgValuesSupported []string              `json:"credential_response_encryption_alg_values_supported,omitempty"`
	CredentialResponseEncryptionEncValuesSupported []string              `json:"credential_response_encryption_enc_values_supported,omitempty"`
	RequireCredentialResponseEncryption            bool                  `json:"require_credential_response_encryption,omitempty"`
	CredentialsSupported                           []CredentialSupported `json:"credentials_supported"`
	Display                                        []DisplayInfo         `json:"display,omitempty"`
}

// OAuthAuthorizationServerMetadata represents OAuth authorization server metadata
type OAuthAuthorizationServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported,omitempty"`
}

// OpenIDConfiguration represents OpenID Connect configuration
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
}

// OAuthError represents OAuth error responses
type OAuthError struct {
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface
func (e *OAuthError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorType + ": " + e.ErrorDescription
	}
	return e.ErrorType
}

// CredentialError represents credential issuance errors
type CredentialError struct {
	ErrorType        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	CNonce           string `json:"c_nonce,omitempty"`
	CNonceExpiresIn  int    `json:"c_nonce_expires_in,omitempty"`
}

// Error implements the error interface
func (e *CredentialError) Error() string {
	if e.ErrorDescription != "" {
		return e.ErrorType + ": " + e.ErrorDescription
	}
	return e.ErrorType
}
