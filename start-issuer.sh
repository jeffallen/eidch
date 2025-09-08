#!/bin/bash

# EID-CH Issuer Service Go Port - Start Script

set -e

echo "Building EID-CH Issuer Service Go Port..."
go build -o issuer-server ./cmd/issuer-server

echo "Setting up configuration..."
export EXTERNAL_URL="http://localhost:8080"
export ISSUER_ID="did:example:test-issuer"
export VERIFICATION_METHOD="did:example:test-issuer#key-1"
export STORAGE_TYPE="jsonfile"
export STORAGE_DATA_DIR="./issuer-data"
export ISSUER_DISPLAY_NAME="EID-CH Test Issuer"
export NONCE_LIFETIME_SECONDS="300"
export CREDENTIAL_EXPIRATION_HOURS="8760"

echo "Starting issuer server..."
echo "External URL: $EXTERNAL_URL"
echo "Issuer ID: $ISSUER_ID"
echo "Storage Type: $STORAGE_TYPE"
echo "Data Directory: $STORAGE_DATA_DIR"
echo ""
echo "API Endpoints:"
echo "  - Issuer Metadata: $EXTERNAL_URL/.well-known/openid-credential-issuer"
echo "  - OpenID Config: $EXTERNAL_URL/.well-known/openid-configuration"
echo "  - Management API: $EXTERNAL_URL/management/api/credentials"
echo "  - Health Check: $EXTERNAL_URL/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo "---"

./issuer-server
