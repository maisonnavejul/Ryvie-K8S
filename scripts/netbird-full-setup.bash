#!/bin/bash

set -euo pipefail

# ==============================
# COLORS FOR OUTPUT
# ==============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ==============================
# CONFIGURATION
# ==============================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${PROJECT_ROOT}/.env"
LOG_FILE="${PROJECT_ROOT}/netbird-full-setup.log"

# Default values
DEFAULT_MAX_RETRIES=60
DEFAULT_RETRY_DELAY=10
DEFAULT_DNS_CHECK_RETRIES=30

# ==============================
# LOGGING FUNCTIONS
# ==============================
log_info() {
    echo -e "${BLUE}ℹ ${NC}$@" | tee -a "$LOG_FILE"
}

log_success() {
    echo -e "${GREEN}✅ ${NC}$@" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}⚠️  ${NC}$@" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}❌ ${NC}$@" | tee -a "$LOG_FILE"
}

log_header() {
    echo "" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}$@${NC}" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}═══════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

# ==============================
# CLEANUP FUNCTION
# ==============================
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Script failed with exit code: $exit_code"
        log_info "Check log file for details: $LOG_FILE"
    fi
}

trap cleanup EXIT

# ==============================
# BANNER
# ==============================
clear
log_header "🚀 NetBird Full Setup Orchestration Script"
log_info "Log file: $LOG_FILE"
log_info "Started at: $(date)"

# ==============================
# CHECK DEPENDENCIES
# ==============================
log_header "📋 Checking Dependencies"

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        log_error "Required command '$1' not found. Please install it."
        exit 1
    fi
    log_success "Found: $1"
}

check_dependency kubectl
check_dependency curl
check_dependency jq
check_dependency dig
check_dependency openssl

# ==============================
# LOAD ENVIRONMENT VARIABLES
# ==============================
log_header "📁 Loading Environment Variables"

if [ ! -f "$ENV_FILE" ]; then
    log_error "Environment file not found: $ENV_FILE"
    log_info "Creating template .env file..."
    
    cat > "$ENV_FILE" <<'ENVEOF'
# OVH API Credentials
# Get these from: https://eu.api.ovh.com/createToken/
OVH_ENDPOINT=ovh-eu
OVH_APPLICATION_KEY=your_application_key_here
OVH_APPLICATION_SECRET=your_application_secret_here
OVH_CONSUMER_KEY=your_consumer_key_here

# Email for TLS certificates
TLS_EMAIL=your-email@example.com

# Optional: Number of retries for DNS/HTTPS checks (default: 60)
MAX_RETRIES=60

# Optional: Delay between retries in seconds (default: 10)
RETRY_DELAY=10n
ENVEOF
    
    log_success "Template .env file created at: $ENV_FILE"
    log_warning "Please edit the .env file with your credentials and run this script again."
    exit 1
fi

# Source the .env file
set -a
source "$ENV_FILE"
set +a

log_success "Environment variables loaded from: $ENV_FILE"

# Validate required variables
if [ -z "${OVH_APPLICATION_KEY:-}" ] || [ "${OVH_APPLICATION_KEY}" = "your_application_key_here" ]; then
    log_error "OVH_APPLICATION_KEY is not set or is using default value"
    exit 1
fi

if [ -z "${OVH_APPLICATION_SECRET:-}" ] || [ "${OVH_APPLICATION_SECRET}" = "your_application_secret_here" ]; then
    log_error "OVH_APPLICATION_SECRET is not set or is using default value"
    exit 1
fi

if [ -z "${OVH_CONSUMER_KEY:-}" ] || [ "${OVH_CONSUMER_KEY}" = "your_consumer_key_here" ]; then
    log_error "OVH_CONSUMER_KEY is not set or is using default value"
    exit 1
fi

if [ -z "${TLS_EMAIL:-}" ] || [ "${TLS_EMAIL}" = "your-email@example.com" ]; then
    log_error "TLS_EMAIL is not set or is using default value"
    exit 1
fi

# Set defaults for optional variables
MAX_RETRIES=${MAX_RETRIES:-$DEFAULT_MAX_RETRIES}
RETRY_DELAY=${RETRY_DELAY:-$DEFAULT_RETRY_DELAY}
OVH_ENDPOINT=${OVH_ENDPOINT:-ovh-eu}

log_success "All required credentials validated"
log_info "OVH Endpoint: $OVH_ENDPOINT"
log_info "TLS Email: $TLS_EMAIL"
log_info "Max Retries: $MAX_RETRIES"
log_info "Retry Delay: ${RETRY_DELAY}s"

# ==============================
# PROMPT FOR DOMAIN NAME
# ==============================
log_header "🌐 Domain Configuration"

read -p "Enter your base domain name (e.g., ryvie.ovh): " BASE_DOMAIN

if [[ -z "$BASE_DOMAIN" ]]; then
    log_error "Domain name is required"
    exit 1
fi

# Validate domain format
if ! [[ "$BASE_DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
    log_error "Invalid domain format: $BASE_DOMAIN"
    exit 1
fi

log_success "Domain validated: $BASE_DOMAIN"

# Define subdomains
PORTAINER_DOMAIN="portainer.$BASE_DOMAIN"
ZITADEL_DOMAIN="zitadel.$BASE_DOMAIN"
NETBIRD_DOMAIN="netbird.$BASE_DOMAIN"

echo ""
log_info "Configuration Summary:"
log_info "  Base Domain:      $BASE_DOMAIN"
log_info "  Portainer:        https://$PORTAINER_DOMAIN"
log_info "  Zitadel:          https://$ZITADEL_DOMAIN"
log_info "  NetBird:          https://$NETBIRD_DOMAIN"
echo ""

read -p "Is this correct? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    log_warning "Setup cancelled by user"
    exit 0
fi

# ==============================
# STEP 1: LAUNCH CADDY
# ==============================
log_header "🚀 STEP 1: Deploying Caddy with OVH DNS"

CADDY_SCRIPT="${SCRIPT_DIR}/caddy-auto.sh"

if [ ! -f "$CADDY_SCRIPT" ]; then
    log_error "Caddy script not found: $CADDY_SCRIPT"
    exit 1
fi

log_info "Launching Caddy deployment..."

# Run caddy-auto.sh with automated input
{
    echo "$OVH_ENDPOINT"
    echo "$OVH_APPLICATION_KEY"
    echo "$OVH_APPLICATION_SECRET"
    echo "$OVH_CONSUMER_KEY"
    echo "$TLS_EMAIL"
} | bash "$CADDY_SCRIPT" 2>&1 | tee -a "$LOG_FILE"

CADDY_EXIT_CODE=${PIPESTATUS[1]}

if [ $CADDY_EXIT_CODE -ne 0 ]; then
    log_error "Caddy deployment failed with exit code: $CADDY_EXIT_CODE"
    exit 1
fi

log_success "Caddy deployment script completed"

# ==============================
# STEP 2: WAIT FOR CADDY SERVICE
# ==============================
log_header "⏳ STEP 2: Waiting for Caddy Service"

log_info "Checking if Caddy service is ready..."

# Wait for Caddy pods to be ready
log_info "Waiting for Caddy pods to be ready (timeout: 300s)..."
if kubectl wait --for=condition=ready --timeout=300s pod -l app=caddy -n caddy-system 2>&1 | tee -a "$LOG_FILE"; then
    log_success "Caddy pods are ready"
else
    log_error "Timeout waiting for Caddy pods"
    log_info "Checking pod status:"
    kubectl get pods -n caddy-system | tee -a "$LOG_FILE"
    exit 1
fi

# Get external IP
log_info "Retrieving Caddy LoadBalancer external IP..."

MAX_IP_WAIT=300
ELAPSED=0
SLEEP_INTERVAL=5
EXTERNAL_IP=""

while [ $ELAPSED -lt $MAX_IP_WAIT ]; do
    EXTERNAL_IP=$(kubectl get service caddy-service -n caddy-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [ -n "$EXTERNAL_IP" ]; then
        log_success "External IP assigned: $EXTERNAL_IP"
        break
    fi
    
    echo -n "."
    sleep $SLEEP_INTERVAL
    ELAPSED=$((ELAPSED + SLEEP_INTERVAL))
done

if [ -z "$EXTERNAL_IP" ]; then
    log_error "Timeout waiting for external IP after ${MAX_IP_WAIT}s"
    kubectl describe service caddy-service -n caddy-system | tee -a "$LOG_FILE"
    exit 1
fi

# ==============================
# STEP 3: VERIFY DNS RESOLUTION
# ==============================
log_header "🔍 STEP 3: Verifying DNS Resolution"

log_info "Checking DNS resolution for domains..."
log_warning "This may take several minutes for DNS propagation..."

check_dns() {
    local domain="$1"
    local expected_ip="$2"
    
    log_info "Checking DNS for: $domain"
    
    local retry=0
    while [ $retry -lt $DEFAULT_DNS_CHECK_RETRIES ]; do
        # Try to resolve the domain
        local resolved_ip=$(dig +short "$domain" @8.8.8.8 | tail -n1 2>/dev/null || echo "")
        
        if [ -n "$resolved_ip" ]; then
            if [ "$resolved_ip" = "$expected_ip" ]; then
                log_success "DNS resolved correctly: $domain -> $resolved_ip"
                return 0
            else
                log_warning "DNS resolved to wrong IP: $domain -> $resolved_ip (expected: $expected_ip)"
            fi
        else
            log_warning "DNS not yet resolved for: $domain (attempt $((retry + 1))/$DEFAULT_DNS_CHECK_RETRIES)"
        fi
        
        retry=$((retry + 1))
        sleep $RETRY_DELAY
    done
    
    log_error "DNS resolution failed for: $domain after $DEFAULT_DNS_CHECK_RETRIES attempts"
    return 1
}

# Check DNS for all domains
DOMAINS=("$PORTAINER_DOMAIN" "$ZITADEL_DOMAIN" "$NETBIRD_DOMAIN")
DNS_SUCCESS=true

for domain in "${DOMAINS[@]}"; do
    if ! check_dns "$domain" "$EXTERNAL_IP"; then
        DNS_SUCCESS=false
        log_warning "Continuing despite DNS resolution failure for: $domain"
        log_warning "You may need to manually configure DNS records"
    fi
done

if [ "$DNS_SUCCESS" = false ]; then
    log_warning "Some DNS checks failed. Please ensure the following records are configured:"
    for domain in "${DOMAINS[@]}"; do
        log_info "  $domain -> $EXTERNAL_IP"
    done
    echo ""
    read -p "Do you want to continue anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Setup cancelled by user"
        exit 0
    fi
fi

# ==============================
# STEP 4: VERIFY HTTPS
# ==============================
log_header "🔒 STEP 4: Verifying HTTPS Availability"

log_info "Checking HTTPS certificate and availability..."
log_warning "This may take several minutes for certificate issuance..."

check_https() {
    local domain="$1"
    
    log_info "Checking HTTPS for: https://$domain"
    
    local retry=0
    while [ $retry -lt $MAX_RETRIES ]; do
        # Try to connect via HTTPS
        local http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain" 2>/dev/null || echo "000")
        
        if [ "$http_code" != "000" ]; then
            log_success "HTTPS is available for: $domain (HTTP $http_code)"
            
            # Check certificate validity
            if curl -s --max-time 10 "https://$domain" > /dev/null 2>&1; then
                log_success "HTTPS certificate is valid for: $domain"
                return 0
            else
                log_warning "HTTPS certificate may have issues for: $domain"
            fi
        else
            log_warning "HTTPS not yet available for: $domain (attempt $((retry + 1))/$MAX_RETRIES)"
        fi
        
        retry=$((retry + 1))
        sleep $RETRY_DELAY
    done
    
    log_error "HTTPS verification failed for: $domain after $MAX_RETRIES attempts"
    return 1
}

# Check HTTPS for all domains
HTTPS_SUCCESS=true

for domain in "${DOMAINS[@]}"; do
    if ! check_https "$domain"; then
        HTTPS_SUCCESS=false
        log_warning "Continuing despite HTTPS verification failure for: $domain"
    fi
done

if [ "$HTTPS_SUCCESS" = false ]; then
    log_warning "Some HTTPS checks failed. The services may not be fully accessible yet."
    echo ""
    read -p "Do you want to continue with NetBird setup anyway? (y/n): " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Setup cancelled by user"
        exit 0
    fi
fi

log_success "Caddy is fully operational!"

# ==============================
# STEP 5: LAUNCH NETBIRD SETUP
# ==============================
log_header "🚀 STEP 5: Launching NetBird Setup"

NETBIRD_SCRIPT="${SCRIPT_DIR}/netbird-step-complet.sh"

if [ ! -f "$NETBIRD_SCRIPT" ]; then
    log_error "NetBird script not found: $NETBIRD_SCRIPT"
    exit 1
fi

log_info "Launching NetBird setup script..."
log_info "This will deploy Zitadel and NetBird with full configuration..."

# Run netbird-step-complet.sh with automated input
{
    echo "$BASE_DOMAIN"
    echo "y"
} | bash "$NETBIRD_SCRIPT" 2>&1 | tee -a "$LOG_FILE"

NETBIRD_EXIT_CODE=${PIPESTATUS[1]}

if [ $NETBIRD_EXIT_CODE -ne 0 ]; then
    log_error "NetBird setup failed with exit code: $NETBIRD_EXIT_CODE"
    exit 1
fi

log_success "NetBird setup completed successfully!"

# ==============================
# FINAL SUMMARY
# ==============================
log_header "✅ SETUP COMPLETE!"

log_success "All components have been deployed successfully!"
echo ""
log_info "📋 Deployment Summary:"
log_info "  External IP:      $EXTERNAL_IP"
log_info "  Portainer:        https://$PORTAINER_DOMAIN"
log_info "  Zitadel:          https://$ZITADEL_DOMAIN"
log_info "  NetBird:          https://$NETBIRD_DOMAIN"
echo ""
log_info "📁 Configuration files:"
log_info "  Setup Info:       ${PROJECT_ROOT}/k8s-manifests/SETUP_INFO.txt"
log_info "  Log File:         $LOG_FILE"
echo ""
log_info "🔍 Next Steps:"
log_info "  1. Review the setup information in SETUP_INFO.txt"
log_info "  2. Access Zitadel and change the default password"
log_info "  3. Access NetBird and complete the initial configuration"
log_info "  4. Monitor the deployments:"
log_info "     kubectl get pods -n caddy-system"
log_info "     kubectl get pods -n netbird"
echo ""
log_success "Setup completed at: $(date)"
log_info "Total execution time: $SECONDS seconds"

exit 0