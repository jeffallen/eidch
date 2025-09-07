#!/bin/bash

# EID-CH Verifier Agent OID4VP Go Port - Start Script

set -e

echo "Building EID-CH Verifier Agent OID4VP Go Port..."
go build -o verification-server ./cmd/verification-server

echo "Loading configuration..."
if [ -f "example.env" ]; then
    export $(grep -v '^#' example.env | xargs)
else
    echo "Warning: example.env not found, using default environment variables"
    export EXTERNAL_URL="http://localhost:8080"
    export VERIFIER_DID="did:example:test-verifier"
    export DID_VERIFICATION_METHOD="did:example:test-verifier#key-1"
fi

echo "Starting server..."
echo "External URL: $EXTERNAL_URL"
echo "Verifier DID: $VERIFIER_DID"
echo "Storage Type: ${STORAGE_TYPE:-memory}"
echo "Server Port: ${SERVER_PORT:-8080}"
echo ""
echo "API Endpoints:"
echo "  - Client Metadata: $EXTERNAL_URL/api/v1/openid-client-metadata.json"
echo "  - Health Check: $EXTERNAL_URL/health"
echo ""
echo "Press Ctrl+C to stop the server"
echo "---"

./verification-server
