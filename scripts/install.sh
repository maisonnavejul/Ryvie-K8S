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
ENV_FILE="${SCRIPT_DIR}/.env"
LOG_FILE="${SCRIPT_DIR}/netbird-installation.log"

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
    echo -e "${YELLOW}════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}$@${NC}" | tee -a "$LOG_FILE"
    echo -e "${YELLOW}════════════════════════════════════════════════════${NC}" | tee -a "$LOG_FILE"
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
log_header "🚀 NetBird + Zitadel + Caddy Complete Installation"
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
# Base domain for all services
BASE_DOMAIN=example.com

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
RETRY_DELAY=10
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
if [ -z "${BASE_DOMAIN:-}" ] || [ "${BASE_DOMAIN}" = "example.com" ]; then
    log_error "BASE_DOMAIN is not set or is using default value"
    exit 1
fi

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

# Define all subdomains
PORTAINER_DOMAIN="portainer.${BASE_DOMAIN}"
ZITADEL_DOMAIN="zitadel.${BASE_DOMAIN}"
NETBIRD_DOMAIN="netbird.${BASE_DOMAIN}"
STUN_DOMAIN="stun.${NETBIRD_DOMAIN}"
ZITADEL_BASE="https://${ZITADEL_DOMAIN}"
NAMESPACE="netbird"

log_success "All required credentials validated"
log_info "Configuration:"
log_info "  Base Domain:      ${BASE_DOMAIN}"
log_info "  Portainer:        https://${PORTAINER_DOMAIN}"
log_info "  Zitadel:          https://${ZITADEL_DOMAIN}"
log_info "  NetBird:          https://${NETBIRD_DOMAIN}"
log_info "  OVH Endpoint:     ${OVH_ENDPOINT}"
log_info "  TLS Email:        ${TLS_EMAIL}"
log_info "  Max Retries:      ${MAX_RETRIES}"
log_info "  Retry Delay:      ${RETRY_DELAY}s"

# ==============================
# CREATE DIRECTORY STRUCTURE
# ==============================
log_header "📁 Creating Directory Structure"

mkdir -p "${SCRIPT_DIR}/k8s-manifests/caddy-system"
mkdir -p "${SCRIPT_DIR}/k8s-manifests/zitadel"
mkdir -p "${SCRIPT_DIR}/k8s-manifests/netbird"

log_success "Directories created"

# ==============================
# STEP 1: DEPLOY CADDY
# ==============================
log_header "🚀 STEP 1: Deploying Caddy with OVH DNS"

log_info "Generating Caddy namespace..."
cat > "${SCRIPT_DIR}/k8s-manifests/caddy-system/namespace.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: caddy-system
EOF

log_info "Generating Caddy ConfigMap..."
cat > "${SCRIPT_DIR}/k8s-manifests/caddy-system/configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: caddy-config
  namespace: caddy-system
data:
  Caddyfile: |
    {
        auto_https disable_redirects
    }

    # -------------------------
    # Portainer
    # -------------------------
    ${PORTAINER_DOMAIN} {
        reverse_proxy portainer-service.portainer.svc.cluster.local:9000 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto {scheme}
            header_up X-Forwarded-Host {host}
            health_uri /api/status
            health_interval 10s
            health_timeout 5s
            health_status 2xx
        }

        log {
            output stdout
            format json
            level INFO
        }
        encode gzip zstd
        header {
            Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
            X-Content-Type-Options "nosniff"
            X-Frame-Options "SAMEORIGIN"
            X-XSS-Protection "1; mode=block"
        }
        header -Server
        tls ${TLS_EMAIL}
    }

    http://${PORTAINER_DOMAIN} {
        redir https://{host}{uri} permanent
    }

    # -------------------------
    # Zitadel
    # -------------------------
    ${ZITADEL_DOMAIN} {
        reverse_proxy h2c://zitadel.netbird.svc.cluster.local:8080 {
            header_up Host ${ZITADEL_DOMAIN}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host ${ZITADEL_DOMAIN}
        }

        encode gzip zstd
        log {
            output stdout
            format json
            level INFO
        }
        header {
            Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
            X-Content-Type-Options "nosniff"
            X-Frame-Options "DENY"
            X-XSS-Protection "1; mode=block"
        }
        header -Server
        tls ${TLS_EMAIL}
    }

    http://${ZITADEL_DOMAIN} {
        redir https://{host}{uri} permanent
    }

    # -------------------------
    # NetBird
    # -------------------------
    ${NETBIRD_DOMAIN} {
        reverse_proxy /api/* netbird-management.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }

        reverse_proxy /management.ManagementService/* h2c://netbird-management.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }

        reverse_proxy /signalexchange.SignalExchange/* h2c://netbird-signal.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }

        reverse_proxy /relay* netbird-relay.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
        }

        reverse_proxy /nb-auth* netbird-dashboard.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
        }

        reverse_proxy /* netbird-dashboard.netbird.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
        }

        encode gzip zstd
        log {
            output stdout
            format json
            level INFO
        }
        header {
            Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
            X-Content-Type-Options "nosniff"
            X-Frame-Options "SAMEORIGIN"
            X-XSS-Protection "1; mode=block"
        }
        header -Server
        tls ${TLS_EMAIL}
    }

    http://${NETBIRD_DOMAIN} {
        redir https://{host}{uri} permanent
    }
EOF

log_info "Generating Caddy PVCs..."
cat > "${SCRIPT_DIR}/k8s-manifests/caddy-system/pvc.yaml" <<EOF
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: caddy-data
  namespace: caddy-system
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: caddy-config-dir
  namespace: caddy-system
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 1Gi
EOF

log_info "Generating Caddy Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/caddy-system/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caddy
  namespace: caddy-system
spec:
  replicas: 2
  selector:
    matchLabels:
      app: caddy
  template:
    metadata:
      labels:
        app: caddy
    spec:
      containers:
        - name: caddy
          image: julescloud/netbird-caddy:latest
          ports:
            - name: http
              containerPort: 80
            - name: https
              containerPort: 443
          volumeMounts:
            - name: caddy-config
              mountPath: /etc/caddy/Caddyfile
              subPath: Caddyfile
            - name: caddy-data
              mountPath: /data
            - name: caddy-config-dir
              mountPath: /config
          env:
            - name: OVH_ENDPOINT
              value: "${OVH_ENDPOINT}"
            - name: OVH_APPLICATION_KEY
              value: "${OVH_APPLICATION_KEY}"
            - name: OVH_APPLICATION_SECRET
              value: "${OVH_APPLICATION_SECRET}"
            - name: OVH_CONSUMER_KEY
              value: "${OVH_CONSUMER_KEY}"
      volumes:
        - name: caddy-config
          configMap:
            name: caddy-config
        - name: caddy-data
          persistentVolumeClaim:
            claimName: caddy-data
        - name: caddy-config-dir
          persistentVolumeClaim:
            claimName: caddy-config-dir
EOF

log_info "Generating Caddy Service..."
cat > "${SCRIPT_DIR}/k8s-manifests/caddy-system/service.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: caddy-service
  namespace: caddy-system
spec:
  type: LoadBalancer
  selector:
    app: caddy
  ports:
    - name: http
      port: 80
      targetPort: 80
      protocol: TCP
    - name: https
      port: 443
      targetPort: 443
      protocol: TCP
EOF

log_info "Applying Caddy manifests..."
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/caddy-system/namespace.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/caddy-system/configmap.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/caddy-system/pvc.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/caddy-system/deployment.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/caddy-system/service.yaml"

log_success "Caddy manifests applied"

# ==============================
# STEP 2: WAIT FOR CADDY
# ==============================
log_header "⏳ STEP 2: Waiting for Caddy Service"

log_info "Waiting for Caddy pods to be ready (timeout: 300s)..."
if kubectl wait --for=condition=ready --timeout=300s pod -l app=caddy -n caddy-system 2>&1 | tee -a "$LOG_FILE"; then
    log_success "Caddy pods are ready"
else
    log_error "Timeout waiting for Caddy pods"
    kubectl get pods -n caddy-system | tee -a "$LOG_FILE"
    exit 1
fi

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
# STEP 3: VERIFY DNS
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
    
    log_warning "DNS resolution failed for: $domain after $DEFAULT_DNS_CHECK_RETRIES attempts"
    log_warning "Continuing anyway - you may need to configure DNS manually"
    return 1
}

DOMAINS=("$PORTAINER_DOMAIN" "$ZITADEL_DOMAIN" "$NETBIRD_DOMAIN")
for domain in "${DOMAINS[@]}"; do
    check_dns "$domain" "$EXTERNAL_IP" || true
done

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
        local http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$domain" 2>/dev/null || echo "000")
        
        if [ "$http_code" != "000" ]; then
            log_success "HTTPS is available for: $domain (HTTP $http_code)"
            
            if curl -s --max-time 10 "https://$domain" > /dev/null 2>&1; then
                log_success "HTTPS certificate is valid for: $domain"
                return 0
            fi
        else
            log_warning "HTTPS not yet available for: $domain (attempt $((retry + 1))/$MAX_RETRIES)"
        fi
        
        retry=$((retry + 1))
        sleep $RETRY_DELAY
    done
    
    log_warning "HTTPS verification failed for: $domain after $MAX_RETRIES attempts"
    log_warning "Continuing anyway - services may not be fully accessible yet"
    return 1
}

for domain in "${DOMAINS[@]}"; do
    check_https "$domain" || true
done

log_success "Caddy is operational"

# ==============================
# STEP 5: DEPLOY ZITADEL
# ==============================
log_header "🚀 STEP 5: Deploying Zitadel"

# Generate random passwords
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZITADEL_MASTERKEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZITADEL_ADMIN_PASSWORD="Admin$(openssl rand -base64 12 | tr -d '=+/')!@#"

log_info "Generating Zitadel manifests..."
cat > "${SCRIPT_DIR}/k8s-manifests/zitadel/zitadel-all.yaml" <<EOF
# Namespace
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE

---
# Secrets PostgreSQL et Zitadel
apiVersion: v1
kind: Secret
metadata:
  name: postgres-secret
  namespace: $NAMESPACE
type: Opaque
stringData:
  POSTGRES_USER: "zitadel"
  POSTGRES_PASSWORD: "$POSTGRES_PASSWORD"
  ZITADEL_USER_PASSWORD: "$POSTGRES_PASSWORD"

---
apiVersion: v1
kind: Secret
metadata:
  name: zitadel-secret
  namespace: $NAMESPACE
type: Opaque
stringData:
  ZITADEL_MASTERKEY: "$ZITADEL_MASTERKEY"

---
# PostgreSQL PersistentVolumeClaim
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi

---
# Zitadel PVC pour machine key
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: zitadel-machinekey-pvc
  namespace: $NAMESPACE
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi

---
# PostgreSQL Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: postgres
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:16-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_USER
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_USER
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_PASSWORD
        - name: POSTGRES_DB
          value: zitadel
        - name: PGDATA
          value: /var/lib/postgresql/data/pgdata
        volumeMounts:
        - name: postgres-storage
          mountPath: /var/lib/postgresql/data
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          exec:
            command: ["pg_isready", "-U", "zitadel"]
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
        readinessProbe:
          exec:
            command: ["pg_isready", "-U", "zitadel"]
          initialDelaySeconds: 5
          periodSeconds: 5
          timeoutSeconds: 5
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc

---
# PostgreSQL Service
apiVersion: v1
kind: Service
metadata:
  name: postgres
  namespace: $NAMESPACE
spec:
  type: ClusterIP
  ports:
  - port: 5432
    targetPort: 5432
    protocol: TCP
    name: postgres
  selector:
    app: postgres

---
# Zitadel Deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: zitadel
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: zitadel
  template:
    metadata:
      labels:
        app: zitadel
    spec:
      initContainers:
      - name: wait-for-postgres
        image: busybox:1.36
        command:
        - sh
        - -c
        - |
          until nc -z postgres 5432; do
            echo "Waiting for PostgreSQL..."
            sleep 2
          done
          echo "PostgreSQL is ready!"
          sleep 5
      
      - name: init-machinekey
        image: busybox:1.36
        command:
        - sh
        - -c
        - |
          mkdir -p /machinekey
          chmod 777 /machinekey
          echo "Machinekey directory initialized"
        volumeMounts:
        - name: machinekey
          mountPath: /machinekey
      
      containers:
      - name: zitadel
        image: ghcr.io/zitadel/zitadel:v2.64.1
        args:
        - start-from-init
        - --masterkeyFromEnv
        - --tlsMode
        - external
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: ZITADEL_MASTERKEY
          valueFrom:
            secretKeyRef:
              name: zitadel-secret
              key: ZITADEL_MASTERKEY
        - name: ZITADEL_EXTERNALSECURE
          value: "true"
        - name: ZITADEL_TLS_ENABLED
          value: "false"
        - name: ZITADEL_EXTERNALPORT
          value: "443"
        - name: ZITADEL_EXTERNALDOMAIN
          value: "${ZITADEL_DOMAIN}"
        - name: ZITADEL_PORT
          value: "8080"
        - name: ZITADEL_LOG_LEVEL
          value: "info"
        - name: ZITADEL_FIRSTINSTANCE_ORG_NAME
          value: "ZITADEL"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME
          value: "zitadel-admin"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD
          value: "$ZITADEL_ADMIN_PASSWORD"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED
          value: "false"
        - name: ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_USERNAME
          value: "zitadel-admin-sa"
        - name: ZITADEL_FIRSTINSTANCE_ORG_MACHINE_MACHINE_NAME
          value: "Admin Service Account"
        - name: ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_SCOPES
          value: "openid profile email urn:zitadel:iam:org:project:id:zitadel:aud"
        - name: ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_EXPIRATIONDATE
          value: "2099-01-01T00:00:00Z"
        - name: ZITADEL_FIRSTINSTANCE_ORG_MACHINE_PAT_PATH
          value: "/machinekey/zitadel-admin-sa.token"
        - name: ZITADEL_DATABASE_POSTGRES_HOST
          value: "postgres"
        - name: ZITADEL_DATABASE_POSTGRES_PORT
          value: "5432"
        - name: ZITADEL_DATABASE_POSTGRES_DATABASE
          value: "zitadel"
        - name: ZITADEL_DATABASE_POSTGRES_USER_USERNAME
          value: "zitadel"
        - name: ZITADEL_DATABASE_POSTGRES_USER_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: ZITADEL_USER_PASSWORD
        - name: ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE
          value: "disable"
        - name: ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME
          value: "zitadel"
        - name: ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: POSTGRES_PASSWORD
        - name: ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE
          value: "disable"
        volumeMounts:
        - name: machinekey
          mountPath: /machinekey
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
        livenessProbe:
          httpGet:
            path: /debug/healthz
            port: 8080
          initialDelaySeconds: 90
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /debug/ready
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 5
          timeoutSeconds: 5
          failureThreshold: 3
      volumes:
      - name: machinekey
        persistentVolumeClaim:
          claimName: zitadel-machinekey-pvc

---
# Zitadel Service
apiVersion: v1
kind: Service
metadata:
  name: zitadel
  namespace: $NAMESPACE
spec:
  type: ClusterIP
  ports:
  - port: 8080
    targetPort: 8080
    protocol: TCP
    name: http
  selector:
    app: zitadel
EOF

log_info "Applying Zitadel manifests..."
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/zitadel/zitadel-all.yaml"

log_info "Waiting for Zitadel pod to be ready (this may take 2-3 minutes)..."
kubectl wait --for=condition=ready pod -l app=zitadel -n $NAMESPACE --timeout=600s

log_success "Zitadel pod is ready!"

# ==============================
# STEP 6: EXTRACT ZITADEL PAT
# ==============================
log_header "🔑 STEP 6: Extracting Zitadel PAT"

ZITADEL_POD=$(kubectl get pod -n $NAMESPACE -l app=zitadel -o jsonpath='{.items[0].metadata.name}')

MAX_RETRIES_PAT=30
RETRY_COUNT=0
ZITADEL_PAT=""

while [ $RETRY_COUNT -lt $MAX_RETRIES_PAT ]; do
    log_info "Attempt $((RETRY_COUNT + 1))/$MAX_RETRIES_PAT to retrieve PAT from logs..."
    
    PAT_OUTPUT=$(kubectl logs -n $NAMESPACE $ZITADEL_POD 2>/dev/null | grep -oP '^[A-Za-z0-9_-]{40,}$' | head -1 || echo "")
    
    if [ -n "$PAT_OUTPUT" ]; then
        ZITADEL_PAT="$PAT_OUTPUT"
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 5
done

if [ -z "$ZITADEL_PAT" ]; then
    log_error "Failed to retrieve PAT from Zitadel pod logs after $MAX_RETRIES_PAT attempts"
    kubectl logs -n $NAMESPACE $ZITADEL_POD --tail=50 | tee -a "$LOG_FILE"
    exit 1
fi

log_success "PAT Retrieved: ${ZITADEL_PAT:0:20}..."

log_info "Waiting for Zitadel API to be fully operational..."
sleep 15

# ==============================
# STEP 7: CONFIGURE ZITADEL
# ==============================
log_header "🔧 STEP 7: Configuring Zitadel for NetBird"

hdr_base=(-H "Authorization: Bearer $ZITADEL_PAT" -H "Content-Type: application/json")

# NetBird configuration
PROJECT_NAME="netbird-project"
DASHBOARD_NAME="Dashboard"
CLI_NAME="Cli"
SERVICE_USER_NAME="netbird-service-account"
ADMIN_EMAIL="admin@${BASE_DOMAIN}"
ADMIN_FIRST_NAME="Admin"
ADMIN_LAST_NAME="User"
ADMIN_USERNAME="admin"

DASHBOARD_REDIRECTS=("https://${NETBIRD_DOMAIN}/nb-auth" "https://${NETBIRD_DOMAIN}/nb-silent-auth" "https://${NETBIRD_DOMAIN}/")
CLI_REDIRECTS=("http://localhost:53000/" "http://localhost:54000/")

log_info "Retrieving organization..."
ORG_JSON=$(curl -fsS "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/me" || true)
ORG_ID=$(echo "$ORG_JSON" | jq -r '.org.id // empty')

if [[ -z "$ORG_ID" ]]; then
    log_warning "No org found via /me. Searching via /orgs/_search..."
    ORG_JSON=$(curl -sS -X POST "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/_search" -d '{"query":{"offset":0,"limit":10}}')
    ORG_ID=$(echo "$ORG_JSON" | jq -r '.result[0].id // empty')
fi

if [[ -z "$ORG_ID" ]]; then
    log_error "Unable to determine organization"
    exit 1
fi
log_success "Org ID: $ORG_ID"

hdr_org=("${hdr_base[@]}" -H "x-zitadel-orgid: $ORG_ID")

# Create project
log_info "Creating project $PROJECT_NAME..."
PROJECT_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects" \
    -d "{\"name\":\"$PROJECT_NAME\"}")
PROJECT_ID=$(echo "$PROJECT_JSON" | jq -r '.id // empty')
log_success "Project ID: $PROJECT_ID"

# Create Dashboard SPA
log_info "Creating SPA application $DASHBOARD_NAME..."
DASHBOARD_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects/$PROJECT_ID/apps/oidc" \
    -d "{
        \"name\":\"$DASHBOARD_NAME\",
        \"redirectUris\":$(printf '%s\n' "${DASHBOARD_REDIRECTS[@]}" | jq -R . | jq -s .),
        \"postLogoutRedirectUris\":[\"https://$NETBIRD_DOMAIN/\"],
        \"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],
        \"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\",\"OIDC_GRANT_TYPE_REFRESH_TOKEN\"],
        \"appType\":\"OIDC_APP_TYPE_USER_AGENT\",
        \"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_NONE\",
        \"version\":\"OIDC_VERSION_1_0\",
        \"devMode\":false,
        \"accessTokenType\":\"OIDC_TOKEN_TYPE_JWT\",
        \"accessTokenRoleAssertion\":true,
        \"skipNativeAppSuccessPage\":true
    }")
DASHBOARD_APP_ID=$(echo "$DASHBOARD_JSON" | jq -r '.clientId // empty')
log_success "Dashboard App Client ID: $DASHBOARD_APP_ID"

# Create CLI SPA
log_info "Creating SPA application $CLI_NAME..."
CLI_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects/$PROJECT_ID/apps/oidc" \
    -d "{
        \"name\":\"$CLI_NAME\",
        \"redirectUris\":$(printf '%s\n' "${CLI_REDIRECTS[@]}" | jq -R . | jq -s .),
        \"postLogoutRedirectUris\":[\"http://localhost:53000/\"],
        \"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],
        \"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\",\"OIDC_GRANT_TYPE_DEVICE_CODE\",\"OIDC_GRANT_TYPE_REFRESH_TOKEN\"],
        \"appType\":\"OIDC_APP_TYPE_USER_AGENT\",
        \"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_NONE\",
        \"version\":\"OIDC_VERSION_1_0\",
        \"devMode\":true,
        \"accessTokenType\":\"OIDC_TOKEN_TYPE_JWT\",
        \"accessTokenRoleAssertion\":true,
        \"skipNativeAppSuccessPage\":true
    }")
CLI_APP_ID=$(echo "$CLI_JSON" | jq -r '.clientId // empty')
log_success "CLI App Client ID: $CLI_APP_ID"

# Create machine service user
log_info "Creating machine service user $SERVICE_USER_NAME..."
SERVICE_USER_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/machine" \
    -d "{
        \"userName\":\"$SERVICE_USER_NAME\",
        \"name\":\"Netbird Service Account\",
        \"description\":\"Netbird Service Account for IDP management\",
        \"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"
    }")
SERVICE_USER_ID=$(echo "$SERVICE_USER_JSON" | jq -r '.userId // empty')
log_success "Service User ID: $SERVICE_USER_ID"

# Generate secret for service user
log_info "Creating secret for service user..."
SERVICE_USER_SECRET_JSON=$(curl -sS -X PUT "${hdr_org[@]}" \
    "$ZITADEL_BASE/management/v1/users/$SERVICE_USER_ID/secret" -d '{}')
SERVICE_USER_CLIENT_ID=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientId // empty')
SERVICE_USER_CLIENT_SECRET=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientSecret // empty')
log_success "Service User Client ID: $SERVICE_USER_CLIENT_ID"
log_success "Service User Secret: ${SERVICE_USER_CLIENT_SECRET:0:20}..."

# Assign service user as ORG_USER_MANAGER
log_info "Assigning service user as ORG_USER_MANAGER..."
curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/orgs/me/members" \
    -d "{\"userId\":\"$SERVICE_USER_ID\",\"roles\":[\"ORG_USER_MANAGER\"]}" >/dev/null
log_success "Service user assigned as ORG_USER_MANAGER"

# Create admin user
log_info "Creating admin user $ADMIN_EMAIL..."
ADMIN_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/human/_import" \
    -d "{
        \"userName\":\"$ADMIN_USERNAME\",
        \"profile\":{\"firstName\":\"$ADMIN_FIRST_NAME\",\"lastName\":\"$ADMIN_LAST_NAME\",\"displayName\":\"$ADMIN_FIRST_NAME $ADMIN_LAST_NAME\"},
        \"email\":{\"email\":\"$ADMIN_EMAIL\",\"isEmailVerified\":true},
        \"password\":\"TempPassword123!\",
        \"passwordChangeRequired\":true
    }")
ADMIN_USER_ID=$(echo "$ADMIN_JSON" | jq -r '.userId // empty')
log_success "Admin User ID: $ADMIN_USER_ID"

# Assign roles
log_info "Assigning ORG_OWNER and IAM_OWNER roles..."
curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/orgs/me/members" \
    -d "{\"userId\":\"$ADMIN_USER_ID\",\"roles\":[\"ORG_OWNER\"]}" >/dev/null
curl -sS -X POST "${hdr_base[@]}" "$ZITADEL_BASE/admin/v1/members" \
    -d "{\"userId\":\"$ADMIN_USER_ID\",\"roles\":[\"IAM_OWNER\"]}" >/dev/null
log_success "Roles assigned"

log_success "Zitadel Configuration Complete!"

# ==============================
# STEP 8: DEPLOY NETBIRD
# ==============================
log_header "🚀 STEP 8: Deploying NetBird"

# Generate NetBird secrets
TURN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
TURN_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
RELAY_AUTH_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

log_info "Generating NetBird management.json ConfigMap..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/01-management-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-management-config
  namespace: $NAMESPACE
data:
  management.json: |
    {
        "Stuns": [
            {
                "Proto": "udp",
                "URI": "stun:${STUN_DOMAIN}:3478",
                "Username": "",
                "Password": null
            }
        ],
        "TURNConfig": {
            "Turns": [
                {
                    "Proto": "udp",
                    "URI": "turn:${STUN_DOMAIN}:3478",
                    "Username": "netbird",
                    "Password": "$TURN_PASSWORD"
                }
            ],
            "CredentialsTTL": "12h",
            "Secret": "$TURN_SECRET",
            "TimeBasedCredentials": false
        },
        "Signal": {
            "Proto": "https",
            "URI": "${NETBIRD_DOMAIN}:443"
        },
        "HttpConfig": {
            "AuthIssuer": "$ZITADEL_BASE",
            "AuthAudience": "$DASHBOARD_APP_ID",
            "OIDCConfigEndpoint": "$ZITADEL_BASE/.well-known/openid-configuration"
        },
        "IdpManagerConfig": {
            "ManagerType": "zitadel",
            "ClientConfig": {
                "Issuer": "$ZITADEL_BASE",
                "TokenEndpoint": "$ZITADEL_BASE/oauth/v2/token",
                "ClientID": "$SERVICE_USER_CLIENT_ID",
                "ClientSecret": "$SERVICE_USER_CLIENT_SECRET",
                "GrantType": "client_credentials"
            },
            "ExtraConfig": {
                "ManagementEndpoint": "$ZITADEL_BASE/management/v1"
            }
        },
        "DeviceAuthorizationFlow": {
            "Provider": "hosted",
            "ProviderConfig": {
                "Audience": "$CLI_APP_ID",
                "ClientID": "$CLI_APP_ID",
                "Scope": "openid"
            }
        },
        "PKCEAuthorizationFlow": {
            "ProviderConfig": {
                "Audience": "$CLI_APP_ID",
                "ClientID": "$CLI_APP_ID",
                "Scope": "openid profile email offline_access",
                "RedirectURLs": ["http://localhost:53000/", "http://localhost:54000/"]
            }
        }
    }
EOF

log_info "Generating NetBird Dashboard ConfigMap..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/02-dashboard-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-dashboard-config
  namespace: $NAMESPACE
data:
  NETBIRD_MGMT_API_ENDPOINT: "https://${NETBIRD_DOMAIN}"
  NETBIRD_MGMT_GRPC_API_ENDPOINT: "https://${NETBIRD_DOMAIN}"
  AUTH_AUDIENCE: "$DASHBOARD_APP_ID"
  AUTH_CLIENT_ID: "$DASHBOARD_APP_ID"
  AUTH_AUTHORITY: "$ZITADEL_BASE"
  USE_AUTH0: "false"
  AUTH_SUPPORTED_SCOPES: "openid profile email offline_access"
  AUTH_REDIRECT_URI: "/nb-auth"
  AUTH_SILENT_REDIRECT_URI: "/nb-silent-auth"
  NGINX_SSL_PORT: "443"
  LETSENCRYPT_DOMAIN: "none"
EOF

log_info "Generating NetBird Relay ConfigMap..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/03-relay-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-relay-config
  namespace: $NAMESPACE
data:
  NB_LOG_LEVEL: "info"
  NB_LISTEN_ADDRESS: ":80"
  NB_EXPOSED_ADDRESS: "rels://${NETBIRD_DOMAIN}:443"
---
apiVersion: v1
kind: Secret
metadata:
  name: netbird-relay-secret
  namespace: $NAMESPACE
type: Opaque
stringData:
  NB_AUTH_SECRET: "$RELAY_AUTH_SECRET"
EOF

log_info "Generating Coturn ConfigMap..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/04-coturn-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: coturn-config
  namespace: $NAMESPACE
data:
  turnserver.conf: |
    listening-port=3478
    tls-listening-port=5349
    
    min-port=49152
    max-port=65535
    
    fingerprint
    lt-cred-mech
    
    user=netbird:$TURN_PASSWORD
    realm=${NETBIRD_DOMAIN}
    
    total-quota=100
    stale-nonce=600
    
    no-multicast-peers
    no-cli
    no-tlsv1
    no-tlsv1_1
    
    verbose
    log-file=stdout
EOF

log_info "Generating NetBird Storage..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/05-storage.yaml" <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: netbird-management-pv
spec:
  capacity:
    storage: 10Gi
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  hostPath:
    path: /tmp/netbird-data
    type: DirectoryOrCreate
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: netbird-management-data
  namespace: $NAMESPACE 
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 10Gi
EOF

log_info "Generating NetBird Management Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/06-management-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-management
  namespace: $NAMESPACE
  labels:
    app: netbird-management
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbird-management
  template:
    metadata:
      labels:
        app: netbird-management
    spec:
      initContainers:
      - name: copy-config
        image: busybox:latest
        command: ['sh', '-c', 'cp /tmp/config/management.json /etc/netbird/management.json && chmod 644 /etc/netbird/management.json']
        volumeMounts:
        - name: management-config-source
          mountPath: /tmp/config
          readOnly: true
        - name: management-config-writable
          mountPath: /etc/netbird
      containers:
      - name: management
        image: netbirdio/management:latest
        ports:
        - containerPort: 80
          name: http
        - containerPort: 443
          name: https
        - containerPort: 9090
          name: metrics
        - containerPort: 33073
          name: grpc-legacy
        args:
        - "--port=80"
        - "--log-file=console"
        - "--log-level=info"
        - "--disable-anonymous-metrics=false"
        - "--single-account-mode-domain=netbird.selfhosted"
        - "--dns-domain=netbird.selfhosted"
        - "--idp-sign-key-refresh-enabled"
        volumeMounts:
        - name: management-config-writable
          mountPath: /etc/netbird
        - name: management-data
          mountPath: /var/lib/netbird
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: management-config-source
        configMap:
          name: netbird-management-config
      - name: management-config-writable
        emptyDir: {}
      - name: management-data
        persistentVolumeClaim:
          claimName: netbird-management-data
---
apiVersion: v1
kind: Service
metadata:
  name: netbird-management
  namespace: $NAMESPACE
spec:
  selector:
    app: netbird-management
  ports:
  - name: http
    port: 80
    targetPort: 80
  - name: https
    port: 443
    targetPort: 443
  - name: metrics
    port: 9090
    targetPort: 9090
  - name: grpc-legacy
    port: 33073
    targetPort: 33073
  type: ClusterIP
EOF

log_info "Generating NetBird Signal Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/07-signal-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-signal
  namespace: $NAMESPACE
  labels:
    app: netbird-signal
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbird-signal
  template:
    metadata:
      labels:
        app: netbird-signal
    spec:
      containers:
      - name: signal
        image: netbirdio/signal:latest
        ports:
        - containerPort: 80
          name: http
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: netbird-signal
  namespace: $NAMESPACE
spec:
  selector:
    app: netbird-signal
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
EOF

log_info "Generating NetBird Relay Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/08-relay-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-relay
  namespace: $NAMESPACE
  labels:
    app: netbird-relay
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbird-relay
  template:
    metadata:
      labels:
        app: netbird-relay
    spec:
      containers:
      - name: relay
        image: netbirdio/relay:latest
        ports:
        - containerPort: 80
          name: http
        envFrom:
        - configMapRef:
            name: netbird-relay-config
        - secretRef:
            name: netbird-relay-secret
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: netbird-relay
  namespace: $NAMESPACE
spec:
  selector:
    app: netbird-relay
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
EOF

log_info "Generating NetBird Dashboard Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/09-dashboard-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-dashboard
  namespace: $NAMESPACE
  labels:
    app: netbird-dashboard
spec:
  replicas: 1
  selector:
    matchLabels:
      app: netbird-dashboard
  template:
    metadata:
      labels:
        app: netbird-dashboard
    spec:
      containers:
      - name: dashboard
        image: netbirdio/dashboard:latest
        ports:
        - containerPort: 80
          name: http
        envFrom:
        - configMapRef:
            name: netbird-dashboard-config
        resources:
          requests:
            memory: "128Mi"
            cpu: "50m"
          limits:
            memory: "256Mi"
            cpu: "200m"
---
apiVersion: v1
kind: Service
metadata:
  name: netbird-dashboard
  namespace: $NAMESPACE
spec:
  selector:
    app: netbird-dashboard
  ports:
  - name: http
    port: 80
    targetPort: 80
  type: ClusterIP
EOF

log_info "Generating Coturn Deployment..."
cat > "${SCRIPT_DIR}/k8s-manifests/netbird/10-coturn-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coturn
  namespace: $NAMESPACE
  labels:
    app: coturn
spec:
  replicas: 1
  selector:
    matchLabels:
      app: coturn
  template:
    metadata:
      labels:
        app: coturn
    spec:
      hostNetwork: true
      dnsPolicy: ClusterFirstWithHostNet
      containers:
      - name: coturn
        image: coturn/coturn:latest
        args:
        - "-c"
        - "/etc/turnserver.conf"
        volumeMounts:
        - name: coturn-config
          mountPath: /etc/turnserver.conf
          subPath: turnserver.conf
          readOnly: true
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
      volumes:
      - name: coturn-config
        configMap:
          name: coturn-config
---
apiVersion: v1
kind: Service
metadata:
  name: coturn
  namespace: $NAMESPACE
spec:
  selector:
    app: coturn
  ports:
  - name: turn-udp
    port: 3478
    targetPort: 3478
    protocol: UDP
  - name: turn-tcp
    port: 3478
    targetPort: 3478
    protocol: TCP
  - name: turn-tls
    port: 5349
    targetPort: 5349
    protocol: TCP
  type: LoadBalancer
EOF

log_info "Applying NetBird manifests..."
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/01-management-config.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/02-dashboard-config.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/03-relay-config.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/04-coturn-config.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/05-storage.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/06-management-deployment.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/07-signal-deployment.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/08-relay-deployment.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/09-dashboard-deployment.yaml"
kubectl apply -f "${SCRIPT_DIR}/k8s-manifests/netbird/10-coturn-deployment.yaml"

log_success "NetBird deployed successfully!"

# ==============================
# SAVE CONFIGURATION
# ==============================
log_header "💾 Saving Configuration"

cat > "${SCRIPT_DIR}/SETUP_INFO.txt" <<EOF
NetBird + Zitadel + Caddy Complete Installation
Generated: $(date)
════════════════════════════════════════════════════

INFRASTRUCTURE:
---------------
External IP: $EXTERNAL_IP

DOMAINS:
--------
Portainer:  https://${PORTAINER_DOMAIN}
Zitadel:    https://${ZITADEL_DOMAIN}
NetBird:    https://${NETBIRD_DOMAIN}
STUN:       ${STUN_DOMAIN}

ZITADEL:
--------
URL: $ZITADEL_BASE
Admin Username: zitadel-admin
Admin Password: $ZITADEL_ADMIN_PASSWORD
PAT: $ZITADEL_PAT
PostgreSQL Password: $POSTGRES_PASSWORD
Masterkey: $ZITADEL_MASTERKEY

Project ID: $PROJECT_ID

Dashboard App Client ID: $DASHBOARD_APP_ID
CLI App Client ID: $CLI_APP_ID

Service User ID: $SERVICE_USER_ID
Service User Client ID: $SERVICE_USER_CLIENT_ID
Service User Client Secret: $SERVICE_USER_CLIENT_SECRET

NETBIRD:
--------
URL: https://${NETBIRD_DOMAIN}
Admin Email: $ADMIN_EMAIL
Admin Username: $ADMIN_USERNAME
Temporary Password: TempPassword123!
Admin User ID: $ADMIN_USER_ID

TURN Password: $TURN_PASSWORD
TURN Secret: $TURN_SECRET
Relay Auth Secret: $RELAY_AUTH_SECRET

DNS CONFIGURATION:
------------------
${PORTAINER_DOMAIN} → $EXTERNAL_IP
${ZITADEL_DOMAIN} → $EXTERNAL_IP
${NETBIRD_DOMAIN} → $EXTERNAL_IP

IMPORTANT:
----------
1. Change the admin password after first login to NetBird
2. Ensure DNS records are configured correctly
3. All services use HTTPS with automatic certificate management
4. Keep this file secure - it contains sensitive credentials

KUBECTL COMMANDS:
-----------------
Monitor Caddy:    kubectl get pods -n caddy-system
Monitor NetBird:  kubectl get pods -n netbird
View logs:        kubectl logs -n netbird -l app=netbird-management
EOF

log_success "Configuration saved to: ${SCRIPT_DIR}/SETUP_INFO.txt"

# ==============================
# FINAL SUMMARY
# ==============================
log_header "✅ INSTALLATION COMPLETE!"

log_success "All components have been deployed successfully!"
echo ""
log_info "📋 Deployment Summary:"
log_info "  External IP:      $EXTERNAL_IP"
log_info "  Portainer:        https://${PORTAINER_DOMAIN}"
log_info "  Zitadel:          https://${ZITADEL_DOMAIN}"
log_info "  NetBird:          https://${NETBIRD_DOMAIN}"
echo ""
log_info "📁 Configuration files:"
log_info "  Setup Info:       ${SCRIPT_DIR}/SETUP_INFO.txt"
log_info "  Log File:         $LOG_FILE"
log_info "  Manifests:        ${SCRIPT_DIR}/k8s-manifests/"
echo ""
log_info "🔐 Credentials:"
log_info "  Zitadel Admin:    zitadel-admin / $ZITADEL_ADMIN_PASSWORD"
log_info "  NetBird Admin:    $ADMIN_EMAIL / TempPassword123!"
echo ""
log_info "🔍 Next Steps:"
log_info "  1. Review the setup information in SETUP_INFO.txt"
log_info "  2. Verify DNS records point to: $EXTERNAL_IP"
log_info "  3. Access Zitadel and change the default password"
log_info "  4. Access NetBird and complete the initial configuration"
log_info "  5. Monitor the deployments:"
log_info "     kubectl get pods -n caddy-system"
log_info "     kubectl get pods -n netbird"
echo ""
log_success "Setup completed at: $(date)"
log_info "Total execution time: $SECONDS seconds"

exit 0