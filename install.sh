#!/bin/bash
set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🚀 Complete Stack Deployment: Caddy + Zitadel + NetBird${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════${NC}\n"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found!${NC}\n"
    echo "Creating .env template..."
    
    cat > .env <<'ENVEOF'
# Domain Configuration
DOMAIN_NAME=ryvie.ovh

# OVH API Credentials
OVH_ENDPOINT=ovh-eu
OVH_APPLICATION_KEY=your_application_key
OVH_APPLICATION_SECRET=your_application_secret
OVH_CONSUMER_KEY=your_consumer_key

# TLS Configuration
TLS_EMAIL=admin@ryvie.ovh
ENVEOF

    echo -e "${GREEN}✅ Created .env template${NC}"
    echo -e "${YELLOW}Please edit .env file with your credentials and run again${NC}\n"
    exit 1
fi

# Load .env file
echo -e "${BLUE}📄 Loading configuration from .env...${NC}"
export $(grep -v '^#' .env | xargs)

# Validate required variables
if [ -z "$DOMAIN_NAME" ] || [ -z "$OVH_APPLICATION_KEY" ] || [ -z "$OVH_APPLICATION_SECRET" ] || [ -z "$OVH_CONSUMER_KEY" ] || [ -z "$TLS_EMAIL" ]; then
    echo -e "${RED}❌ Missing required variables in .env file${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Configuration loaded${NC}\n"

# Display configuration
echo -e "${YELLOW}Configuration:${NC}"
echo -e "  Domain: ${BLUE}$DOMAIN_NAME${NC}"
echo -e "  OVH Endpoint: ${BLUE}$OVH_ENDPOINT${NC}"
echo -e "  TLS Email: ${BLUE}$TLS_EMAIL${NC}"
echo -e "  Zitadel URL: ${BLUE}https://zitadel.$DOMAIN_NAME${NC}"
echo -e "  NetBird URL: ${BLUE}https://netbird.$DOMAIN_NAME${NC}"
echo -e "  Portainer URL: ${BLUE}https://portainer.$DOMAIN_NAME${NC}\n"

read -p "Continue with deployment? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${RED}❌ Deployment cancelled${NC}"
    exit 1
fi

# Check dependencies
need() { command -v "$1" >/dev/null 2>&1 || { echo -e "${RED}❌ '$1' not found. Install it.${NC}"; exit 1; }; }
need kubectl
need curl
need jq
need openssl
need dig

# Map OVH endpoint to API URL
case "$OVH_ENDPOINT" in
    ovh-eu) API_URL="https://eu.api.ovh.com/1.0" ;;
    ovh-ca) API_URL="https://ca.api.ovh.com/1.0" ;;
    ovh-us) API_URL="https://api.us.ovhcloud.com/1.0" ;;
    *) echo -e "${RED}❌ Unknown OVH_ENDPOINT: $OVH_ENDPOINT${NC}"; exit 1 ;;
esac

NAMESPACE="netbird"
ZITADEL_BASE="https://zitadel.$DOMAIN_NAME"
NETBIRD_DOMAIN="netbird.$DOMAIN_NAME"

# ════════════════════════════════════════════════════════════════════
# PART 1: DEPLOY CADDY WITH SSL
# ════════════════════════════════════════════════════════════════════

echo -e "\n${YELLOW}════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}📦 STEP 1: Deploying Caddy (SSL/TLS Handler)${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════${NC}\n"

CADDY_DIR="k8s-manifests/caddy-system"
mkdir -p "$CADDY_DIR"

# Generate Caddy manifests
cat > "$CADDY_DIR/namespace.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: caddy-system
EOF

cat > "$CADDY_DIR/configmap.yaml" <<EOF
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

    portainer.$DOMAIN_NAME {
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
        tls $TLS_EMAIL
    }

    http://portainer.$DOMAIN_NAME {
        redir https://{host}{uri} permanent
    }

    zitadel.$DOMAIN_NAME {
        reverse_proxy h2c://zitadel.$NAMESPACE.svc.cluster.local:8080 {
            header_up Host zitadel.$DOMAIN_NAME
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host zitadel.$DOMAIN_NAME
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
        tls $TLS_EMAIL
    }

    http://zitadel.$DOMAIN_NAME {
        redir https://{host}{uri} permanent
    }

    netbird.$DOMAIN_NAME {
        reverse_proxy /api/* netbird-management.$NAMESPACE.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }
        reverse_proxy /management.ManagementService/* h2c://netbird-management.$NAMESPACE.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }
        reverse_proxy /signalexchange.SignalExchange/* h2c://netbird-signal.$NAMESPACE.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
            header_up Authorization {http.request.header.Authorization}
        }
        reverse_proxy /relay* netbird-relay.$NAMESPACE.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
        }
        reverse_proxy /nb-auth* netbird-dashboard.$NAMESPACE.svc.cluster.local:80 {
            header_up Host {host}
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host {host}
        }
        reverse_proxy /* netbird-dashboard.$NAMESPACE.svc.cluster.local:80 {
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
        tls $TLS_EMAIL
    }

    http://netbird.$DOMAIN_NAME {
        redir https://{host}{uri} permanent
    }
EOF

cat > "$CADDY_DIR/pvc.yaml" <<EOF
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

cat > "$CADDY_DIR/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: caddy
  namespace: caddy-system
spec:
  replicas: 1
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
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 512Mi
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
              value: "$OVH_ENDPOINT"
            - name: OVH_APPLICATION_KEY
              value: "$OVH_APPLICATION_KEY"
            - name: OVH_APPLICATION_SECRET
              value: "$OVH_APPLICATION_SECRET"
            - name: OVH_CONSUMER_KEY
              value: "$OVH_CONSUMER_KEY"
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

cat > "$CADDY_DIR/service.yaml" <<EOF
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

cat > "$CADDY_DIR/hpa.yaml" <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: caddy-hpa
  namespace: caddy-system
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: caddy
  minReplicas: 1
  maxReplicas: 3
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
EOF

echo -e "${BLUE}Applying Caddy manifests...${NC}"
kubectl apply -f "$CADDY_DIR/namespace.yaml"
kubectl apply -f "$CADDY_DIR/configmap.yaml"
kubectl apply -f "$CADDY_DIR/pvc.yaml"
kubectl apply -f "$CADDY_DIR/deployment.yaml"
kubectl apply -f "$CADDY_DIR/service.yaml"
kubectl apply -f "$CADDY_DIR/hpa.yaml"

echo -e "${YELLOW}Waiting for Caddy deployment...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment/caddy -n caddy-system
kubectl wait --for=condition=ready --timeout=300s pod -l app=caddy -n caddy-system

echo -e "${YELLOW}Waiting for LoadBalancer IP...${NC}"
MAX_WAIT=600
ELAPSED=0
SLEEP_INTERVAL=5

while [ $ELAPSED -lt $MAX_WAIT ]; do
    EXTERNAL_IP=$(kubectl get service caddy-service -n caddy-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [ -n "$EXTERNAL_IP" ]; then
        echo -e "\n${GREEN}✅ LoadBalancer IP: $EXTERNAL_IP${NC}\n"
        break
    fi
    
    echo -n "."
    sleep $SLEEP_INTERVAL
    ELAPSED=$((ELAPSED + SLEEP_INTERVAL))
done

if [ -z "$EXTERNAL_IP" ]; then
    echo -e "\n${RED}❌ Timeout waiting for LoadBalancer IP${NC}"
    exit 1
fi

# OVH API functions
ovh_api_call() {
    local method="$1"
    local path="$2"
    local body="$3"
    
    local timestamp=$(date +%s)
    local url="${API_URL}${path}"
    
    if [ -z "$body" ]; then
        local signature="\$1\$$(echo -n "${OVH_APPLICATION_SECRET}+${OVH_CONSUMER_KEY}+${method}+${url}++${timestamp}" | shasum -a 1 | cut -d' ' -f1)"
    else
        local signature="\$1\$$(echo -n "${OVH_APPLICATION_SECRET}+${OVH_CONSUMER_KEY}+${method}+${url}+${body}+${timestamp}" | shasum -a 1 | cut -d' ' -f1)"
    fi
    
    if [ -z "$body" ]; then
        curl -s -X "$method" "$url" \
            -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
            -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
            -H "X-Ovh-Signature: $signature" \
            -H "X-Ovh-Timestamp: $timestamp" \
            -H "Content-Type: application/json"
    else
        curl -s -X "$method" "$url" \
            -H "X-Ovh-Application: $OVH_APPLICATION_KEY" \
            -H "X-Ovh-Consumer: $OVH_CONSUMER_KEY" \
            -H "X-Ovh-Signature: $signature" \
            -H "X-Ovh-Timestamp: $timestamp" \
            -H "Content-Type: application/json" \
            -d "$body"
    fi
}

update_dns_record() {
    local subdomain="$1"
    local target_ip="$2"
    
    echo -e "${BLUE}Processing DNS: ${subdomain}.${DOMAIN_NAME}${NC}"
    
    local record_ids=$(ovh_api_call "GET" "/domain/zone/${DOMAIN_NAME}/record?fieldType=A&subDomain=${subdomain}")
    
    if [ "$record_ids" == "[]" ] || [ -z "$record_ids" ]; then
        echo -e "${YELLOW}  Creating new A record...${NC}"
        local create_body="{\"fieldType\":\"A\",\"subDomain\":\"${subdomain}\",\"target\":\"${target_ip}\",\"ttl\":300}"
        ovh_api_call "POST" "/domain/zone/${DOMAIN_NAME}/record" "$create_body" > /dev/null
        echo -e "${GREEN}  ✓ A record created${NC}"
    else
        local record_id=$(echo "$record_ids" | grep -oP '\d+' | head -n1)
        local current_record=$(ovh_api_call "GET" "/domain/zone/${DOMAIN_NAME}/record/${record_id}")
        local current_ip=$(echo "$current_record" | grep -oP '"target":"[^"]*"' | cut -d'"' -f4)
        
        if [ "$current_ip" == "$target_ip" ]; then
            echo -e "${GREEN}  ✓ Record already correct${NC}"
        else
            echo -e "${YELLOW}  Updating: $current_ip → $target_ip${NC}"
            local update_body="{\"target\":\"${target_ip}\",\"ttl\":300}"
            ovh_api_call "PUT" "/domain/zone/${DOMAIN_NAME}/record/${record_id}" "$update_body" > /dev/null
            echo -e "${GREEN}  ✓ A record updated${NC}"
        fi
    fi
}

echo -e "${YELLOW}Updating DNS records...${NC}"
SUBDOMAINS=("portainer" "zitadel" "netbird")
DNS_UPDATES_MADE=false

for subdomain in "${SUBDOMAINS[@]}"; do
    RESOLVED_IP=$(dig +short "${subdomain}.${DOMAIN_NAME}" @8.8.8.8 | tail -n1)
    
    if [ -z "$RESOLVED_IP" ] || [ "$RESOLVED_IP" != "$EXTERNAL_IP" ]; then
        update_dns_record "$subdomain" "$EXTERNAL_IP"
        DNS_UPDATES_MADE=true
    else
        echo -e "${GREEN}DNS already correct: ${subdomain}.${DOMAIN_NAME} → $EXTERNAL_IP${NC}"
    fi
done

if [ "$DNS_UPDATES_MADE" = true ]; then
    echo -e "${YELLOW}Refreshing DNS zone...${NC}"
    ovh_api_call "POST" "/domain/zone/${DOMAIN_NAME}/refresh" "" > /dev/null
    echo -e "${GREEN}✓ DNS zone refreshed${NC}"
    
    echo -e "${YELLOW}Waiting for DNS propagation (30s)...${NC}"
    sleep 30
    
    echo -e "${YELLOW}Restarting Caddy to obtain SSL certificates...${NC}"
    kubectl rollout restart deployment/caddy -n caddy-system
    kubectl rollout status deployment/caddy -n caddy-system --timeout=300s
    
    echo -e "${YELLOW}Waiting for SSL certificate issuance (60s)...${NC}"
    sleep 60
fi

echo -e "${GREEN}✅ Caddy deployed with SSL${NC}\n"

# ════════════════════════════════════════════════════════════════════
# PART 2: DEPLOY ZITADEL
# ════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🔐 STEP 2: Deploying Zitadel${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════${NC}\n"

ZITADEL_DIR="k8s-manifests/zitadel"
mkdir -p "$ZITADEL_DIR"

POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZITADEL_MASTERKEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZITADEL_ADMIN_PASSWORD="ZitadelAdmin123!"
ZITADEL_ADMIN_USERNAME="zitadel-admin"
ZITADEL_ADMIN_EMAIL="admin@${DOMAIN_NAME}"

cat > "$ZITADEL_DIR/zitadel-all.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
---
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
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
      volumes:
      - name: postgres-storage
        persistentVolumeClaim:
          claimName: postgres-pvc
---
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
  selector:
    app: postgres
---
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
          sleep 5
      - name: init-machinekey
        image: busybox:1.36
        command:
        - sh
        - -c
        - |
          mkdir -p /machinekey
          chmod 777 /machinekey
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
          value: "zitadel.$DOMAIN_NAME"
        - name: ZITADEL_PORT
          value: "8080"
        - name: ZITADEL_LOG_LEVEL
          value: "info"
        - name: ZITADEL_FIRSTINSTANCE_ORG_NAME
          value: "ZITADEL"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_USERNAME
          value: "$ZITADEL_ADMIN_USERNAME"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORD
          value: "$ZITADEL_ADMIN_PASSWORD"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_PASSWORDCHANGEREQUIRED
          value: "false"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_ADDRESS
          value: "$ZITADEL_ADMIN_EMAIL"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_EMAIL_VERIFIED
          value: "true"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_FIRSTNAME
          value: "Zitadel"
        - name: ZITADEL_FIRSTINSTANCE_ORG_HUMAN_LASTNAME
          value: "Admin"
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
            memory: "1Gi"
            cpu: "500m"
          limits:
            memory: "3Gi"
            cpu: "2000m"
      volumes:
      - name: machinekey
        persistentVolumeClaim:
          claimName: zitadel-machinekey-pvc
---
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
  selector:
    app: zitadel
EOF

kubectl apply -f "$ZITADEL_DIR/zitadel-all.yaml"

echo -e "${YELLOW}Waiting for Zitadel pod (may take 2-3 minutes)...${NC}"
kubectl wait --for=condition=ready pod -l app=zitadel -n $NAMESPACE --timeout=600s

echo -e "${GREEN}✅ Zitadel deployed${NC}\n"

# Extract PAT
ZITADEL_POD=$(kubectl get pod -n $NAMESPACE -l app=zitadel -o jsonpath='{.items[0].metadata.name}')
MAX_RETRIES=30
RETRY_COUNT=0
ZITADEL_PAT=""

echo -e "${YELLOW}Extracting PAT from Zitadel...${NC}"
while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    PAT_OUTPUT=$(kubectl logs -n $NAMESPACE $ZITADEL_POD 2>/dev/null | grep -oP '^[A-Za-z0-9_-]{40,}$' | head -1 || echo "")
    
    if [ -n "$PAT_OUTPUT" ]; then
        ZITADEL_PAT="$PAT_OUTPUT"
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 5
done

if [ -z "$ZITADEL_PAT" ]; then
    echo -e "${RED}❌ Failed to retrieve PAT${NC}"
    exit 1
fi

echo -e "${GREEN}✅ PAT Retrieved${NC}\n"

# ════════════════════════════════════════════════════════════════════
# PART 3: CONFIGURE ZITADEL FOR NETBIRD
# ════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}⚙️  STEP 3: Configuring Zitadel for NetBird${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════${NC}\n"

# Wait for Zitadel API to be fully operational
echo -e "${YELLOW}Waiting for Zitadel API to be fully operational...${NC}"
echo -e "${BLUE}This may take 2-5 minutes after SSL certificate issuance${NC}\n"

MAX_API_RETRIES=60
API_RETRY_COUNT=0
API_READY=false

while [ $API_RETRY_COUNT -lt $MAX_API_RETRIES ]; do
    echo -ne "\r${YELLOW}Attempt $((API_RETRY_COUNT + 1))/$MAX_API_RETRIES: Checking Zitadel API health...${NC}"
    
    # Check health endpoint first
    HEALTH_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$ZITADEL_BASE/debug/healthz" 2>/dev/null || echo "000")
    
    if [ "$HEALTH_STATUS" == "200" ]; then
        echo -e "\n${GREEN}✅ Health endpoint responding${NC}"
        
        # Now try the management API with PAT
        TEST_RESPONSE=$(curl -s -w "\n%{http_code}" -H "Authorization: Bearer $ZITADEL_PAT" -H "Content-Type: application/json" "$ZITADEL_BASE/management/v1/orgs/me" 2>/dev/null || echo "")
        TEST_HTTP_CODE=$(echo "$TEST_RESPONSE" | tail -n1)
        TEST_BODY=$(echo "$TEST_RESPONSE" | sed '$d')
        
        if [ "$TEST_HTTP_CODE" == "200" ]; then
            # Verify we got valid JSON with org data
            if echo "$TEST_BODY" | jq -e '.org.id' >/dev/null 2>&1; then
                echo -e "${GREEN}✅ Management API fully operational${NC}\n"
                API_READY=true
                break
            else
                echo -e "\n${YELLOW}⚠ API responded but data not ready yet${NC}"
            fi
        elif [ "$TEST_HTTP_CODE" == "401" ]; then
            echo -e "\n${RED}❌ Authentication failed - PAT may be invalid${NC}"
            echo -e "${YELLOW}PAT: ${ZITADEL_PAT:0:20}...${NC}"
            exit 1
        elif [ "$TEST_HTTP_CODE" == "502" ] || [ "$TEST_HTTP_CODE" == "503" ]; then
            echo -e "\n${YELLOW}⚠ Service temporarily unavailable (${TEST_HTTP_CODE})${NC}"
        else
            echo -e "\n${YELLOW}⚠ Unexpected response: HTTP $TEST_HTTP_CODE${NC}"
        fi
    else
        echo -ne " (health: $HEALTH_STATUS)"
    fi
    
    API_RETRY_COUNT=$((API_RETRY_COUNT + 1))
    sleep 5
done

if [ "$API_READY" = false ]; then
    echo -e "\n${RED}❌ Zitadel API failed to become ready after $((MAX_API_RETRIES * 5)) seconds${NC}"
    echo -e "${YELLOW}Debugging information:${NC}"
    echo -e "${BLUE}Pod status:${NC}"
    kubectl get pods -n $NAMESPACE -l app=zitadel
    echo -e "\n${BLUE}Recent logs:${NC}"
    kubectl logs -n $NAMESPACE -l app=zitadel --tail=30
    echo -e "\n${BLUE}Service endpoints:${NC}"
    kubectl get svc -n $NAMESPACE zitadel
    echo -e "\n${YELLOW}Try checking:${NC}"
    echo -e "  1. SSL certificate: ${BLUE}curl -I https://zitadel.$DOMAIN_NAME${NC}"
    echo -e "  2. Health endpoint: ${BLUE}curl https://zitadel.$DOMAIN_NAME/debug/healthz${NC}"
    echo -e "  3. Pod logs: ${BLUE}kubectl logs -n $NAMESPACE -l app=zitadel${NC}"
    exit 1
fi

hdr_base=(-H "Authorization: Bearer $ZITADEL_PAT" -H "Content-Type: application/json")

echo -e "${BLUE}Retrieving organization information...${NC}"
ORG_JSON=$(curl -fsS "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/me" || true)
ORG_ID=$(echo "$ORG_JSON" | jq -r '.org.id // empty')

if [[ -z "$ORG_ID" ]]; then
    echo -e "${YELLOW}Trying alternative method to get org...${NC}"
    ORG_JSON=$(curl -sS -X POST "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/_search" -d '{"query":{"offset":0,"limit":10}}')
    ORG_ID=$(echo "$ORG_JSON" | jq -r '.result[0].id // empty')
fi

if [[ -z "$ORG_ID" ]]; then
    echo -e "${RED}❌ Unable to determine organization${NC}"
    echo -e "${YELLOW}API Response:${NC}"
    echo "$ORG_JSON" | jq '.' 2>/dev/null || echo "$ORG_JSON"
    exit 1
fi

echo -e "${GREEN}✅ Org ID: $ORG_ID${NC}"
hdr_org=("${hdr_base[@]}" -H "x-zitadel-orgid: $ORG_ID")

PROJECT_NAME="netbird-project"
DASHBOARD_NAME="Dashboard"
CLI_NAME="Cli"
SERVICE_USER_NAME="netbird-service-account"

DASHBOARD_REDIRECTS=("https://$NETBIRD_DOMAIN/nb-auth" "https://$NETBIRD_DOMAIN/nb-silent-auth" "https://$NETBIRD_DOMAIN/")
CLI_REDIRECTS=("http://localhost:53000/" "http://localhost:54000/")

echo -e "${BLUE}Creating project...${NC}"
PROJECT_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects" -d "{\"name\":\"$PROJECT_NAME\"}")
PROJECT_ID=$(echo "$PROJECT_JSON" | jq -r '.id // empty')

echo -e "${BLUE}Creating Dashboard app...${NC}"
DASHBOARD_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects/$PROJECT_ID/apps/oidc" \
    -d "{\"name\":\"$DASHBOARD_NAME\",\"redirectUris\":$(printf '%s\n' "${DASHBOARD_REDIRECTS[@]}" | jq -R . | jq -s .),\"postLogoutRedirectUris\":[\"https://$NETBIRD_DOMAIN/\"],\"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],\"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\",\"OIDC_GRANT_TYPE_REFRESH_TOKEN\"],\"appType\":\"OIDC_APP_TYPE_USER_AGENT\",\"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_NONE\",\"version\":\"OIDC_VERSION_1_0\",\"devMode\":false,\"accessTokenType\":\"OIDC_TOKEN_TYPE_JWT\",\"accessTokenRoleAssertion\":true,\"skipNativeAppSuccessPage\":true}")
DASHBOARD_APP_ID=$(echo "$DASHBOARD_JSON" | jq -r '.clientId // empty')

echo -e "${BLUE}Creating CLI app...${NC}"
CLI_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects/$PROJECT_ID/apps/oidc" \
    -d "{\"name\":\"$CLI_NAME\",\"redirectUris\":$(printf '%s\n' "${CLI_REDIRECTS[@]}" | jq -R . | jq -s .),\"postLogoutRedirectUris\":[\"http://localhost:53000/\"],\"responseTypes\":[\"OIDC_RESPONSE_TYPE_CODE\"],\"grantTypes\":[\"OIDC_GRANT_TYPE_AUTHORIZATION_CODE\",\"OIDC_GRANT_TYPE_DEVICE_CODE\",\"OIDC_GRANT_TYPE_REFRESH_TOKEN\"],\"appType\":\"OIDC_APP_TYPE_USER_AGENT\",\"authMethodType\":\"OIDC_AUTH_METHOD_TYPE_NONE\",\"version\":\"OIDC_VERSION_1_0\",\"devMode\":true,\"accessTokenType\":\"OIDC_TOKEN_TYPE_JWT\",\"accessTokenRoleAssertion\":true,\"skipNativeAppSuccessPage\":true}")
CLI_APP_ID=$(echo "$CLI_JSON" | jq -r '.clientId // empty')

echo -e "${BLUE}Creating service user...${NC}"
SERVICE_USER_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/machine" \
    -d "{\"userName\":\"$SERVICE_USER_NAME\",\"name\":\"Netbird Service Account\",\"description\":\"Netbird Service Account for IDP management\",\"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"}")
SERVICE_USER_ID=$(echo "$SERVICE_USER_JSON" | jq -r '.userId // empty')

SERVICE_USER_SECRET_JSON=$(curl -sS -X PUT "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/$SERVICE_USER_ID/secret" -d '{}')
SERVICE_USER_CLIENT_ID=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientId // empty')
SERVICE_USER_CLIENT_SECRET=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientSecret // empty')

curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/orgs/me/members" -d "{\"userId\":\"$SERVICE_USER_ID\",\"roles\":[\"ORG_USER_MANAGER\"]}" >/dev/null

echo -e "${GREEN}✅ Zitadel configured for NetBird${NC}\n"

# ════════════════════════════════════════════════════════════════════
# PART 4: DEPLOY NETBIRD
# ════════════════════════════════════════════════════════════════════

echo -e "${YELLOW}════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}🌐 STEP 4: Deploying NetBird${NC}"
echo -e "${YELLOW}════════════════════════════════════════════════════${NC}\n"

NETBIRD_DIR="k8s-manifests/netbird"
mkdir -p "$NETBIRD_DIR"

TURN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
TURN_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
RELAY_AUTH_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

cat > "$NETBIRD_DIR/01-management-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-management-config
  namespace: $NAMESPACE
data:
  management.json: |
    {
        "Stuns": [{"Proto": "udp", "URI": "stun:stun.$NETBIRD_DOMAIN:3478", "Username": "", "Password": null}],
        "TURNConfig": {
            "Turns": [{"Proto": "udp", "URI": "turn:stun.$NETBIRD_DOMAIN:3478", "Username": "netbird", "Password": "$TURN_PASSWORD"}],
            "CredentialsTTL": "12h",
            "Secret": "$TURN_SECRET",
            "TimeBasedCredentials": false
        },
        "Signal": {"Proto": "https", "URI": "$NETBIRD_DOMAIN:443"},
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
            "ExtraConfig": {"ManagementEndpoint": "$ZITADEL_BASE/management/v1"}
        },
        "DeviceAuthorizationFlow": {
            "Provider": "hosted",
            "ProviderConfig": {"Audience": "$CLI_APP_ID", "ClientID": "$CLI_APP_ID", "Scope": "openid"}
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

cat > "$NETBIRD_DIR/02-dashboard-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-dashboard-config
  namespace: $NAMESPACE
data:
  NETBIRD_MGMT_API_ENDPOINT: "https://$NETBIRD_DOMAIN"
  NETBIRD_MGMT_GRPC_API_ENDPOINT: "https://$NETBIRD_DOMAIN"
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

cat > "$NETBIRD_DIR/03-relay-config.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-relay-config
  namespace: $NAMESPACE
data:
  NB_LOG_LEVEL: "info"
  NB_LISTEN_ADDRESS: ":80"
  NB_EXPOSED_ADDRESS: "rels://$NETBIRD_DOMAIN:443"
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

cat > "$NETBIRD_DIR/04-coturn-config.yaml" <<EOF
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
    realm=$NETBIRD_DOMAIN
    total-quota=100
    stale-nonce=600
    no-multicast-peers
    no-cli
    no-tlsv1
    no-tlsv1_1
    verbose
    log-file=stdout
EOF

cat > "$NETBIRD_DIR/05-storage.yaml" <<EOF
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

cat > "$NETBIRD_DIR/06-management-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-management
  namespace: $NAMESPACE
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
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "2Gi"
            cpu: "1500m"
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
  type: ClusterIP
EOF

cat > "$NETBIRD_DIR/07-signal-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-signal
  namespace: $NAMESPACE
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
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
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

cat > "$NETBIRD_DIR/08-relay-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-relay
  namespace: $NAMESPACE
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
        envFrom:
        - configMapRef:
            name: netbird-relay-config
        - secretRef:
            name: netbird-relay-secret
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
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

cat > "$NETBIRD_DIR/09-dashboard-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-dashboard
  namespace: $NAMESPACE
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
        envFrom:
        - configMapRef:
            name: netbird-dashboard-config
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
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

cat > "$NETBIRD_DIR/10-coturn-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: coturn
  namespace: $NAMESPACE
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
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "1Gi"
            cpu: "1500m"
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

cat > "$NETBIRD_DIR/11-autoscaling.yaml" <<EOF
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: netbird-relay-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: netbird-relay
  minReplicas: 1
  maxReplicas: 6
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: coturn-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: coturn
  minReplicas: 1
  maxReplicas: 4
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: netbird-signal-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: netbird-signal
  minReplicas: 1
  maxReplicas: 3
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: netbird-management-hpa
  namespace: $NAMESPACE
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: netbird-management
  minReplicas: 1
  maxReplicas: 3
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
EOF

echo -e "${BLUE}Applying NetBird manifests...${NC}"
for file in "$NETBIRD_DIR"/*.yaml; do
    kubectl apply -f "$file"
done

echo -e "${GREEN}✅ NetBird deployed${NC}\n"

# ════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════════════

echo -e "${GREEN}════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}✅ DEPLOYMENT COMPLETE!${NC}"
echo -e "${GREEN}════════════════════════════════════════════════════${NC}\n"

cat > k8s-manifests/DEPLOYMENT_INFO.txt <<EOF
Complete Stack Deployment Summary
Generated: $(date)
════════════════════════════════════════════════════

INFRASTRUCTURE:
--------------
LoadBalancer IP: $EXTERNAL_IP
Domain: $DOMAIN_NAME

SERVICES:
---------
Portainer: https://portainer.$DOMAIN_NAME
Zitadel:   https://zitadel.$DOMAIN_NAME
NetBird:   https://netbird.$DOMAIN_NAME

ZITADEL CREDENTIALS:
-------------------
URL: $ZITADEL_BASE
Login Email: $ZITADEL_ADMIN_EMAIL
Username: $ZITADEL_ADMIN_USERNAME
Password: $ZITADEL_ADMIN_PASSWORD
PAT: $ZITADEL_PAT
PostgreSQL Password: $POSTGRES_PASSWORD
Masterkey: $ZITADEL_MASTERKEY

IMPORTANT: Use the EMAIL ($ZITADEL_ADMIN_EMAIL) to login to Zitadel, not the username!

Project ID: $PROJECT_ID
Dashboard Client ID: $DASHBOARD_APP_ID
CLI Client ID: $CLI_APP_ID
Service User Client ID: $SERVICE_USER_CLIENT_ID
Service User Secret: $SERVICE_USER_CLIENT_SECRET

NETBIRD SECRETS:
---------------
TURN Password: $TURN_PASSWORD
TURN Secret: $TURN_SECRET
Relay Auth Secret: $RELAY_AUTH_SECRET

MONITORING:
-----------
kubectl get pods -n caddy-system
kubectl get pods -n $NAMESPACE
kubectl get hpa -n caddy-system
kubectl get hpa -n $NAMESPACE
kubectl get svc -n caddy-system
kubectl get svc -n $NAMESPACE

SSL CERTIFICATE CHECK:
---------------------
openssl s_client -servername zitadel.$DOMAIN_NAME -connect zitadel.$DOMAIN_NAME:443 </dev/null 2>/dev/null | openssl x509 -noout -dates
EOF

echo -e "${BLUE}📋 Deployment Info:${NC}"
echo -e "  LoadBalancer IP: ${GREEN}$EXTERNAL_IP${NC}"
echo -e "  Portainer: ${GREEN}https://portainer.$DOMAIN_NAME${NC}"
echo -e "  Zitadel: ${GREEN}https://zitadel.$DOMAIN_NAME${NC}"
echo -e "  NetBird: ${GREEN}https://netbird.$DOMAIN_NAME${NC}\n"

echo -e "${BLUE}🔐 Zitadel Login:${NC}"
echo -e "  URL: ${GREEN}https://zitadel.$DOMAIN_NAME${NC}"
echo -e "  Email (Login): ${GREEN}$ZITADEL_ADMIN_EMAIL${NC}"
echo -e "  Username: ${GREEN}$ZITADEL_ADMIN_USERNAME${NC}"
echo -e "  Password: ${GREEN}$ZITADEL_ADMIN_PASSWORD${NC}"
echo -e "  ${YELLOW}⚠ Use EMAIL to login, not username${NC}\n"

echo -e "${BLUE}📋 NetBird Admin Login:${NC}"
echo -e "  URL: ${GREEN}https://netbird.$DOMAIN_NAME${NC}"
echo -e "  Use Zitadel email and password above to authenticate\n"

echo -e "${YELLOW}📊 Check Status:${NC}"
echo -e "  ${BLUE}kubectl get pods -n caddy-system${NC}"
echo -e "  ${BLUE}kubectl get pods -n $NAMESPACE${NC}"
echo -e "  ${BLUE}kubectl get hpa -n $NAMESPACE${NC}\n"

echo -e "${GREEN}💾 Full deployment info saved to: k8s-manifests/DEPLOYMENT_INFO.txt${NC}\n"