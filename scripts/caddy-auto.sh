#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}=== Caddy Service Deployment & IP Retrieval Script ===${NC}\n"

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Load environment variables from .env file
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo -e "${RED}Error: .env file not found at $ENV_FILE${NC}"
    exit 1
fi

echo -e "${YELLOW}Loading configuration from .env file...${NC}"
source "$ENV_FILE"

# Validate required variables
if [ -z "$BASE_DOMAIN" ]; then
    echo -e "${RED}Error: BASE_DOMAIN is not set in .env file${NC}"
    exit 1
fi

if [ -z "$OVH_APPLICATION_KEY" ] || [ -z "$OVH_APPLICATION_SECRET" ] || [ -z "$OVH_CONSUMER_KEY" ]; then
    echo -e "${RED}Error: OVH credentials are not set in .env file${NC}"
    exit 1
fi

if [ -z "$TLS_EMAIL" ]; then
    echo -e "${RED}Error: TLS_EMAIL is not set in .env file${NC}"
    exit 1
fi

# Set default for OVH_ENDPOINT if not provided
OVH_ENDPOINT=${OVH_ENDPOINT:-ovh-eu}

echo -e "${GREEN}Configuration loaded successfully${NC}"
echo -e "${GREEN}  BASE_DOMAIN: $BASE_DOMAIN${NC}"
echo -e "${GREEN}  TLS_EMAIL: $TLS_EMAIL${NC}"
echo -e "${GREEN}  OVH_ENDPOINT: $OVH_ENDPOINT${NC}\n"

# Create manifests directory
MANIFEST_DIR="k8s-manifests/caddy-system"
echo -e "${YELLOW}Creating manifests directory: ${MANIFEST_DIR}${NC}"
mkdir -p "$MANIFEST_DIR"
echo -e "${GREEN}✓ Directory created${NC}\n"

# Generate namespace manifest
echo -e "${YELLOW}Generating namespace.yaml...${NC}"
cat > "$MANIFEST_DIR/namespace.yaml" <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: caddy-system
EOF
echo -e "${GREEN}✓ namespace.yaml created${NC}\n"

# Generate configmap manifest with OVH credentials
echo -e "${YELLOW}Generating configmap.yaml...${NC}"
cat > "$MANIFEST_DIR/configmap.yaml" <<'EOF'
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
    portainer.BASE_DOMAIN_PLACEHOLDER {
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
        tls TLS_EMAIL_PLACEHOLDER
    }

    http://portainer.BASE_DOMAIN_PLACEHOLDER {
        redir https://{host}{uri} permanent
    }

    # -------------------------
    # Zitadel
    # -------------------------
    zitadel.BASE_DOMAIN_PLACEHOLDER {
        reverse_proxy h2c://zitadel.netbird.svc.cluster.local:8080 {
            header_up Host zitadel.BASE_DOMAIN_PLACEHOLDER
            header_up X-Real-IP {remote_host}
            header_up X-Forwarded-Proto https
            header_up X-Forwarded-Host zitadel.BASE_DOMAIN_PLACEHOLDER
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
        tls TLS_EMAIL_PLACEHOLDER
    }

    http://zitadel.BASE_DOMAIN_PLACEHOLDER {
        redir https://{host}{uri} permanent
    }

    # -------------------------
    # NetBird
    # -------------------------
    netbird.BASE_DOMAIN_PLACEHOLDER {
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
        tls TLS_EMAIL_PLACEHOLDER
    }

    http://netbird.BASE_DOMAIN_PLACEHOLDER {
        redir https://{host}{uri} permanent
    }
EOF

# Replace placeholders
sed -i "s/TLS_EMAIL_PLACEHOLDER/$TLS_EMAIL/g" "$MANIFEST_DIR/configmap.yaml"
sed -i "s/BASE_DOMAIN_PLACEHOLDER/$BASE_DOMAIN/g" "$MANIFEST_DIR/configmap.yaml"
echo -e "${GREEN}✓ configmap.yaml created${NC}\n"

# Generate PVC manifests
echo -e "${YELLOW}Generating pvc.yaml...${NC}"
cat > "$MANIFEST_DIR/pvc.yaml" <<EOF
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
echo -e "${GREEN}✓ pvc.yaml created${NC}\n"

# Generate deployment manifest
echo -e "${YELLOW}Generating deployment.yaml...${NC}"
cat > "$MANIFEST_DIR/deployment.yaml" <<EOF
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
echo -e "${GREEN}✓ deployment.yaml created${NC}\n"

# Generate service manifest
echo -e "${YELLOW}Generating service.yaml...${NC}"
cat > "$MANIFEST_DIR/service.yaml" <<EOF
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
echo -e "${GREEN}✓ service.yaml created${NC}\n"

echo -e "${GREEN}All manifests created in ${MANIFEST_DIR}/${NC}\n"

# Apply manifests
echo -e "${YELLOW}Applying Kubernetes manifests...${NC}"
kubectl apply -f "$MANIFEST_DIR/namespace.yaml"
kubectl apply -f "$MANIFEST_DIR/configmap.yaml"
kubectl apply -f "$MANIFEST_DIR/pvc.yaml"
kubectl apply -f "$MANIFEST_DIR/deployment.yaml"
kubectl apply -f "$MANIFEST_DIR/service.yaml"
echo -e "${GREEN}✓ Manifests applied${NC}\n"

# Wait for deployment to be ready
echo -e "${YELLOW}Waiting for Caddy deployment to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment/caddy -n caddy-system
echo -e "${GREEN}✓ Deployment is ready${NC}\n"

# Wait for at least one pod to be ready
echo -e "${YELLOW}Waiting for Caddy pods to be ready...${NC}"
kubectl wait --for=condition=ready --timeout=300s pod -l app=caddy -n caddy-system
echo -e "${GREEN}✓ Pods are ready${NC}\n"

# Wait for service to get external IP
echo -e "${YELLOW}Waiting for LoadBalancer to assign external IP...${NC}"
echo -e "${YELLOW}This may take several minutes...${NC}\n"

MAX_WAIT=600  # 10 minutes
ELAPSED=0
SLEEP_INTERVAL=5

while [ $ELAPSED -lt $MAX_WAIT ]; do
    EXTERNAL_IP=$(kubectl get service caddy-service -n caddy-system -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "")
    
    if [ -n "$EXTERNAL_IP" ]; then
        echo -e "\n${GREEN}=== SUCCESS ===${NC}"
        echo -e "${GREEN}External IP assigned: ${EXTERNAL_IP}${NC}\n"
        
        echo -e "${YELLOW}Service Details:${NC}"
        kubectl get service caddy-service -n caddy-system
        
        echo -e "\n${YELLOW}Next steps:${NC}"
        echo "1. Update your DNS records to point to: ${EXTERNAL_IP}"
        echo "2. Verify the service is accessible:"
        echo "   curl -I https://portainer.$BASE_DOMAIN"
        echo "   curl -I https://zitadel.$BASE_DOMAIN"
        echo "   curl -I https://netbird.$BASE_DOMAIN"
        
        exit 0
    fi
    
    echo -n "."
    sleep $SLEEP_INTERVAL
    ELAPSED=$((ELAPSED + SLEEP_INTERVAL))
done

echo -e "\n${RED}Timeout waiting for external IP after ${MAX_WAIT} seconds${NC}"
echo -e "${YELLOW}Checking service status:${NC}"
kubectl describe service caddy-service -n caddy-system
exit 1