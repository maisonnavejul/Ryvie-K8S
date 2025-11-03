#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}🚀 Ryvie K8S Complete Installation${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

# Load environment variables from .env file
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}❌ Error: .env file not found at $ENV_FILE${NC}"
    echo -e "${YELLOW}Please create a .env file with the required variables${NC}"
    exit 1
fi

echo -e "${YELLOW}📄 Loading environment variables from .env...${NC}"
source "$ENV_FILE"

# Validate required variables
if [ -z "$BASE_DOMAIN" ]; then
    echo -e "${RED}❌ Error: BASE_DOMAIN is not set in .env file${NC}"
    exit 1
fi

if [ -z "$OVH_APPLICATION_KEY" ] || [ -z "$OVH_APPLICATION_SECRET" ] || [ -z "$OVH_CONSUMER_KEY" ]; then
    echo -e "${RED}❌ Error: OVH credentials are not set in .env file${NC}"
    exit 1
fi

if [ -z "$TLS_EMAIL" ]; then
    echo -e "${RED}❌ Error: TLS_EMAIL is not set in .env file${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Environment variables loaded successfully${NC}"
echo -e "${GREEN}   BASE_DOMAIN: $BASE_DOMAIN${NC}"
echo -e "${GREEN}   TLS_EMAIL: $TLS_EMAIL${NC}"
echo ""

# Step 1: Deploy Caddy
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}📦 STEP 1: Deploying Caddy Reverse Proxy${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

CADDY_SCRIPT="$SCRIPT_DIR/caddy-auto.sh"

if [ ! -f "$CADDY_SCRIPT" ]; then
    echo -e "${RED}❌ Error: caddy-auto.sh not found at $CADDY_SCRIPT${NC}"
    exit 1
fi

# Make sure the script is executable
chmod +x "$CADDY_SCRIPT"

# Run Caddy deployment script
echo -e "${YELLOW}🚀 Running Caddy deployment...${NC}"
"$CADDY_SCRIPT"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ Caddy deployment failed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Caddy deployment completed${NC}"
echo ""

# Step 2: Wait for and verify Zitadel certificate
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}🔐 STEP 2: Verifying Zitadel TLS Certificate${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

ZITADEL_DOMAIN="zitadel.$BASE_DOMAIN"
echo -e "${YELLOW}Checking for TLS certificate for $ZITADEL_DOMAIN...${NC}"

# Function to check if certificate exists in Caddy pod
check_certificate() {
    local domain=$1
    local namespace="caddy-system"
    
    # Get the first Caddy pod
    local pod=$(kubectl get pods -n $namespace -l app=caddy -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$pod" ]; then
        echo -e "${RED}❌ No Caddy pod found${NC}"
        return 1
    fi
    
    # Check if certificate exists in the data directory
    # Caddy stores certificates in /data/caddy/certificates/
    kubectl exec -n $namespace $pod -- sh -c "ls -la /data/caddy/certificates/acme-v02.api.letsencrypt.org-directory/$domain/ 2>/dev/null" > /dev/null 2>&1
    return $?
}

# Wait for certificate to be issued
MAX_WAIT=600  # 10 minutes
ELAPSED=0
SLEEP_INTERVAL=10

echo -e "${YELLOW}Waiting for Caddy to obtain TLS certificate for $ZITADEL_DOMAIN...${NC}"
echo -e "${YELLOW}This may take a few minutes as Caddy requests the certificate from Let's Encrypt...${NC}"
echo ""

while [ $ELAPSED -lt $MAX_WAIT ]; do
    if check_certificate "$ZITADEL_DOMAIN"; then
        echo -e "\n${GREEN}✅ TLS certificate for $ZITADEL_DOMAIN has been obtained!${NC}"
        break
    fi
    
    echo -n "."
    sleep $SLEEP_INTERVAL
    ELAPSED=$((ELAPSED + SLEEP_INTERVAL))
done

if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo -e "\n${YELLOW}⚠️  Warning: Certificate check timed out after ${MAX_WAIT} seconds${NC}"
    echo -e "${YELLOW}Continuing anyway - certificate may still be in progress...${NC}"
fi

echo ""

# Additional verification: Check if Zitadel endpoint is accessible via HTTPS
echo -e "${YELLOW}Verifying HTTPS connectivity to $ZITADEL_DOMAIN...${NC}"

HTTPS_CHECK_RETRIES=5
HTTPS_CHECK_COUNT=0

while [ $HTTPS_CHECK_COUNT -lt $HTTPS_CHECK_RETRIES ]; do
    if curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$ZITADEL_DOMAIN" | grep -q "[0-9]"; then
        echo -e "${GREEN}✅ HTTPS endpoint is responding${NC}"
        break
    fi
    
    HTTPS_CHECK_COUNT=$((HTTPS_CHECK_COUNT + 1))
    if [ $HTTPS_CHECK_COUNT -lt $HTTPS_CHECK_RETRIES ]; then
        echo -e "${YELLOW}⏳ Attempt $HTTPS_CHECK_COUNT/$HTTPS_CHECK_RETRIES - Waiting for HTTPS endpoint...${NC}"
        sleep 5
    fi
done

if [ $HTTPS_CHECK_COUNT -ge $HTTPS_CHECK_RETRIES ]; then
    echo -e "${YELLOW}⚠️  Warning: Could not verify HTTPS connectivity${NC}"
    echo -e "${YELLOW}This may be normal if DNS is not yet propagated${NC}"
fi

echo ""

# Step 3: Deploy NetBird and Zitadel
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}📦 STEP 3: Deploying NetBird and Zitadel${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""

NETBIRD_SCRIPT="$SCRIPT_DIR/netbird-step-complet.sh"

if [ ! -f "$NETBIRD_SCRIPT" ]; then
    echo -e "${RED}❌ Error: netbird-step-complet.sh not found at $NETBIRD_SCRIPT${NC}"
    exit 1
fi

# Make sure the script is executable
chmod +x "$NETBIRD_SCRIPT"

# Run NetBird deployment script with BASE_DOMAIN as input
echo -e "${YELLOW}🚀 Running NetBird and Zitadel deployment...${NC}"
echo -e "${YELLOW}Using domain: $BASE_DOMAIN${NC}"
echo ""

# Pass the domain automatically to the script
echo "$BASE_DOMAIN" | "$NETBIRD_SCRIPT"

if [ $? -ne 0 ]; then
    echo -e "${RED}❌ NetBird deployment failed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ NetBird and Zitadel deployment completed${NC}"
echo ""

# Final summary
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}✅ INSTALLATION COMPLETE!${NC}"
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
echo ""
echo -e "${GREEN}All components have been deployed successfully:${NC}"
echo -e "${GREEN}  ✓ Caddy Reverse Proxy${NC}"
echo -e "${GREEN}  ✓ Zitadel Identity Provider${NC}"
echo -e "${GREEN}  ✓ NetBird VPN Platform${NC}"
echo ""
echo -e "${YELLOW}📋 Access URLs:${NC}"
echo -e "${YELLOW}  Portainer: https://portainer.$BASE_DOMAIN${NC}"
echo -e "${YELLOW}  Zitadel:   https://zitadel.$BASE_DOMAIN${NC}"
echo -e "${YELLOW}  NetBird:   https://netbird.$BASE_DOMAIN${NC}"
echo ""
echo -e "${YELLOW}📄 Configuration details saved to: k8s-manifests/SETUP_INFO.txt${NC}"
echo ""
echo -e "${BLUE}════════════════════════════════════════════════════${NC}"
