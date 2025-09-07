package jwt

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// Header represents a JWT header
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid,omitempty"`
}

// Claims represents JWT claims
type Claims struct {
	Issuer    string                 `json:"iss,omitempty"`
	Subject   string                 `json:"sub,omitempty"`
	Audience  string                 `json:"aud,omitempty"`
	IssuedAt  int64                  `json:"iat,omitempty"`
	Expiry    int64                  `json:"exp,omitempty"`
	NotBefore int64                  `json:"nbf,omitempty"`
	JWTID     string                 `json:"jti,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// MarshalJSON implements custom JSON marshaling for Claims
func (c *Claims) MarshalJSON() ([]byte, error) {
	type Alias Claims
	base := (*Alias)(c)

	// Create a map to hold all claims
	allClaims := make(map[string]interface{})

	// Marshal the base struct to get standard claims
	baseBytes, err := json.Marshal(base)
	if err != nil {
		return nil, err
	}

	// Unmarshal into map to combine with extra claims
	if err := json.Unmarshal(baseBytes, &allClaims); err != nil {
		return nil, err
	}

	// Add extra claims
	for k, v := range c.Extra {
		allClaims[k] = v
	}

	return json.Marshal(allClaims)
}

// Signer defines the interface for JWT signing
type Signer interface {
	Sign(token string) (string, error)
	Algorithm() string
}

// ES256Signer implements ECDSA P-256 SHA-256 signing
type ES256Signer struct {
	privateKey *ecdsa.PrivateKey
	keyID      string
}

// NewES256Signer creates a new ES256 signer from PEM encoded private key
func NewES256Signer(privateKeyPEM, keyID string) (*ES256Signer, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format
		parsedKey, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("failed to parse EC private key: %v (also tried PKCS8: %v)", err, err2)
		}
		var ok bool
		privateKey, ok = parsedKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parsed key is not an ECDSA private key")
		}
	}

	return &ES256Signer{
		privateKey: privateKey,
		keyID:      keyID,
	}, nil
}

// Algorithm returns the algorithm name
func (s *ES256Signer) Algorithm() string {
	return "ES256"
}

// Sign signs the JWT token
func (s *ES256Signer) Sign(token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	r, sig, err := ecdsa.Sign(rand.Reader, s.privateKey, hash[:])
	if err != nil {
		return "", err
	}

	// Convert to fixed-length byte array (32 bytes each for r and s)
	signature := make([]byte, 64)
	r.FillBytes(signature[0:32])
	sig.FillBytes(signature[32:64])

	return base64.RawURLEncoding.EncodeToString(signature), nil
}

// CreateToken creates a new JWT token with the given claims
func CreateToken(claims *Claims, signer Signer) (string, error) {
	// Create header
	header := Header{
		Alg: signer.Algorithm(),
		Typ: "JWT",
	}

	if es256Signer, ok := signer.(*ES256Signer); ok {
		header.Kid = es256Signer.keyID
	}

	// Set default timestamps if not set
	now := time.Now().Unix()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.Expiry == 0 {
		claims.Expiry = now + 300 // 5 minutes default
	}

	// Marshal header and claims
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	// Encode header and claims
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerBytes)
	claimsEncoded := base64.RawURLEncoding.EncodeToString(claimsBytes)

	// Create signing input
	signingInput := headerEncoded + "." + claimsEncoded

	// Sign
	signature, err := signer.Sign(signingInput)
	if err != nil {
		return "", err
	}

	return signingInput + "." + signature, nil
}

// ParseToken parses a JWT token and returns header and claims (without verification)
func ParseToken(token string) (*Header, *Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %v", err)
	}

	var header Header
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal header: %v", err)
	}

	// Decode claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode claims: %v", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal claims: %v", err)
	}

	return &header, &claims, nil
}
