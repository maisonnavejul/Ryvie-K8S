#!/bin/bash
set -euo pipefail

# ==============================
# USER INPUT
# ==============================
echo "════════════════════════════════════════════════════"
echo "🚀 NetBird + Zitadel Automated Setup"
echo "════════════════════════════════════════════════════"
echo ""

# Ask for domain name
read -p "Enter your domain name (e.g., ryvie.ovh): " BASE_DOMAIN

if [[ -z "$BASE_DOMAIN" ]]; then
    echo "❌ Domain name is required"
    exit 1
fi

# Confirm with user
echo ""
echo "Configuration:"
echo "  Base Domain: $BASE_DOMAIN"
echo "  Zitadel URL: https://zitadel.$BASE_DOMAIN"
echo "  NetBird URL: https://netbird.$BASE_DOMAIN"
echo ""
read -p "Is this correct? (y/n): " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "❌ Setup cancelled"
    exit 1
fi

# ==============================
# CONFIGURATION
# ==============================
ZITADEL_BASE="https://zitadel.$BASE_DOMAIN"
NETBIRD_DOMAIN="netbird.$BASE_DOMAIN"
NAMESPACE="netbird"

PROJECT_NAME="netbird-project"
DASHBOARD_NAME="Dashboard"
CLI_NAME="Cli"
SERVICE_USER_NAME="netbird-service-account"
ADMIN_EMAIL="admin@$BASE_DOMAIN"
ADMIN_FIRST_NAME="Admin"
ADMIN_LAST_NAME="User"
ADMIN_USERNAME="admin"

DASHBOARD_REDIRECTS=("https://$NETBIRD_DOMAIN/nb-auth" "https://$NETBIRD_DOMAIN/nb-silent-auth" "https://$NETBIRD_DOMAIN/")
CLI_REDIRECTS=("http://localhost:53000/" "http://localhost:54000/")

# Check dependencies
need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ '$1' not found. Install it."; exit 1; }; }
need kubectl
need curl
need jq
need openssl

echo ""
echo "════════════════════════════════════════════════════"
echo "📁 STEP 1: Creating Directory Structure"
echo "════════════════════════════════════════════════════"
echo ""

# Create directory structure
mkdir -p k8s-manifests/zitadel
mkdir -p k8s-manifests/netbird

echo "✅ Directories created:"
echo "   k8s-manifests/"
echo "   ├── zitadel/"
echo "   └── netbird/"
echo ""

echo "════════════════════════════════════════════════════"
echo "📝 STEP 2: Generating Zitadel Manifests"
echo "════════════════════════════════════════════════════"
echo ""

# Generate random passwords for Zitadel
POSTGRES_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
ZITADEL_MASTERKEY=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

# Generate a password that meets Zitadel complexity requirements:
# - At least 8 characters
# - Contains uppercase, lowercase, number, and symbol
ZITADEL_ADMIN_PASSWORD="Admin$(openssl rand -base64 12 | tr -d '=+/')!@#"

# Create Zitadel manifests
cat > k8s-manifests/zitadel/zitadel-all.yaml <<EOF
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
          value: "zitadel.$BASE_DOMAIN"
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

echo "✅ Zitadel manifests generated"

echo ""
echo "════════════════════════════════════════════════════"
echo "🚀 STEP 3: Deploying Zitadel"
echo "════════════════════════════════════════════════════"
echo ""

# Deploy Zitadel
kubectl apply -f k8s-manifests/zitadel/zitadel-all.yaml

echo "⏳ Waiting for Zitadel pod to be ready (this may take 2-3 minutes)..."
kubectl wait --for=condition=ready pod -l app=zitadel -n $NAMESPACE --timeout=600s

echo "✅ Zitadel pod is ready!"
echo ""

echo "🔑 Extracting PAT from Zitadel logs..."
# Get the pod name
ZITADEL_POD=$(kubectl get pod -n $NAMESPACE -l app=zitadel -o jsonpath='{.items[0].metadata.name}')

# Extract PAT from the pod logs
MAX_RETRIES=30
RETRY_COUNT=0
ZITADEL_PAT=""

while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
    echo "Attempt $((RETRY_COUNT + 1))/$MAX_RETRIES to retrieve PAT from logs..."
    
    # The PAT appears in logs as a standalone line with 40+ alphanumeric characters
    PAT_OUTPUT=$(kubectl logs -n $NAMESPACE $ZITADEL_POD 2>/dev/null | grep -oP '^[A-Za-z0-9_-]{40,}$' | head -1 || echo "")
    
    if [ -n "$PAT_OUTPUT" ]; then
        ZITADEL_PAT="$PAT_OUTPUT"
        break
    fi
    
    RETRY_COUNT=$((RETRY_COUNT + 1))
    sleep 5
done

if [ -z "$ZITADEL_PAT" ]; then
    echo "❌ Failed to retrieve PAT from Zitadel pod logs after $MAX_RETRIES attempts"
    echo "Checking pod logs for errors:"
    kubectl logs -n $NAMESPACE $ZITADEL_POD --tail=50
    exit 1
fi

echo "✅ PAT Retrieved: ${ZITADEL_PAT:0:20}..."
echo ""

echo "⏳ Waiting for Zitadel API to be fully operational..."
sleep 15

echo "════════════════════════════════════════════════════"
echo "🚀 STEP 4: Configuring Zitadel for NetBird"
echo "════════════════════════════════════════════════════"
echo ""

hdr_base=(-H "Authorization: Bearer $ZITADEL_PAT" -H "Content-Type: application/json")

echo "🔎 Retrieving organization..."
ORG_JSON=$(curl -fsS "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/me" || true)
ORG_ID=$(echo "$ORG_JSON" | jq -r '.org.id // empty')

if [[ -z "$ORG_ID" ]]; then
    echo "⚠️  No org found via /me. Searching via /orgs/_search..."
    ORG_JSON=$(curl -sS -X POST "${hdr_base[@]}" "$ZITADEL_BASE/management/v1/orgs/_search" -d '{"query":{"offset":0,"limit":10}}')
    ORG_ID=$(echo "$ORG_JSON" | jq -r '.result[0].id // empty')
fi

if [[ -z "$ORG_ID" ]]; then
    echo "❌ Unable to determine organization."
    exit 1
fi
echo "✅ Org ID: $ORG_ID"

hdr_org=("${hdr_base[@]}" -H "x-zitadel-orgid: $ORG_ID")

# Create project
echo "🚀 Creating project $PROJECT_NAME..."
PROJECT_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/projects" \
    -d "{\"name\":\"$PROJECT_NAME\"}")
PROJECT_ID=$(echo "$PROJECT_JSON" | jq -r '.id // empty')
echo "✅ Project ID: $PROJECT_ID"

# Create NetBird Dashboard SPA
echo "🚀 Creating SPA application $DASHBOARD_NAME..."
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
echo "✅ Dashboard App Client ID: $DASHBOARD_APP_ID"

# Create NetBird CLI SPA
echo "🚀 Creating SPA application $CLI_NAME..."
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
echo "✅ CLI App Client ID: $CLI_APP_ID"

# Create machine service user
echo "🚀 Creating machine service user $SERVICE_USER_NAME..."
SERVICE_USER_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/machine" \
    -d "{
        \"userName\":\"$SERVICE_USER_NAME\",
        \"name\":\"Netbird Service Account\",
        \"description\":\"Netbird Service Account for IDP management\",
        \"accessTokenType\":\"ACCESS_TOKEN_TYPE_JWT\"
    }")
SERVICE_USER_ID=$(echo "$SERVICE_USER_JSON" | jq -r '.userId // empty')
echo "✅ Service User ID: $SERVICE_USER_ID"

# Generate secret for the service user
echo "🔑 Creating secret for service user..."
SERVICE_USER_SECRET_JSON=$(curl -sS -X PUT "${hdr_org[@]}" \
    "$ZITADEL_BASE/management/v1/users/$SERVICE_USER_ID/secret" -d '{}')
SERVICE_USER_CLIENT_ID=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientId // empty')
SERVICE_USER_CLIENT_SECRET=$(echo "$SERVICE_USER_SECRET_JSON" | jq -r '.clientSecret // empty')
echo "✅ Service User Client ID: $SERVICE_USER_CLIENT_ID"
echo "✅ Service User Secret: $SERVICE_USER_CLIENT_SECRET"

# Assign service user as ORG_USER_MANAGER
echo "🔧 Assigning service user as ORG_USER_MANAGER..."
curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/orgs/me/members" \
    -d "{\"userId\":\"$SERVICE_USER_ID\",\"roles\":[\"ORG_USER_MANAGER\"]}" >/dev/null
echo "✅ Service user assigned as ORG_USER_MANAGER"

# Create admin user
echo "🚀 Creating admin user $ADMIN_EMAIL..."
ADMIN_JSON=$(curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/users/human/_import" \
    -d "{
        \"userName\":\"$ADMIN_USERNAME\",
        \"profile\":{\"firstName\":\"$ADMIN_FIRST_NAME\",\"lastName\":\"$ADMIN_LAST_NAME\",\"displayName\":\"$ADMIN_FIRST_NAME $ADMIN_LAST_NAME\"},
        \"email\":{\"email\":\"$ADMIN_EMAIL\",\"isEmailVerified\":true},
        \"password\":\"TempPassword123!\",
        \"passwordChangeRequired\":true
    }")
ADMIN_USER_ID=$(echo "$ADMIN_JSON" | jq -r '.userId // empty')
echo "✅ Admin User ID: $ADMIN_USER_ID"

# Assign roles ORG_OWNER & IAM_OWNER
echo "🔧 Assigning ORG_OWNER and IAM_OWNER roles..."
curl -sS -X POST "${hdr_org[@]}" "$ZITADEL_BASE/management/v1/orgs/me/members" \
    -d "{\"userId\":\"$ADMIN_USER_ID\",\"roles\":[\"ORG_OWNER\"]}" >/dev/null
curl -sS -X POST "${hdr_base[@]}" "$ZITADEL_BASE/admin/v1/members" \
    -d "{\"userId\":\"$ADMIN_USER_ID\",\"roles\":[\"IAM_OWNER\"]}" >/dev/null
echo "✅ Roles assigned"

echo ""
echo "════════════════════════════════════════════════════"
echo "✅ Zitadel Configuration Complete!"
echo "════════════════════════════════════════════════════"

# Generate secure random passwords for NetBird
TURN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
TURN_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
RELAY_AUTH_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

echo ""
echo "════════════════════════════════════════════════════"
echo "📝 STEP 5: Generating NetBird Kubernetes Manifests"
echo "════════════════════════════════════════════════════"
echo ""

# Create management.json ConfigMap
cat > k8s-manifests/netbird/01-management-config.yaml <<EOF
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
                "URI": "stun:stun.$NETBIRD_DOMAIN:3478",
                "Username": "",
                "Password": null
            }
        ],
        "TURNConfig": {
            "Turns": [
                {
                    "Proto": "udp",
                    "URI": "turn:stun.$NETBIRD_DOMAIN:3478",
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
            "URI": "$NETBIRD_DOMAIN:443"
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

# Create Dashboard ConfigMap
cat > k8s-manifests/netbird/02-dashboard-config.yaml <<EOF
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

# Create Relay ConfigMap
cat > k8s-manifests/netbird/03-relay-config.yaml <<EOF
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

# Create Coturn ConfigMap
cat > k8s-manifests/netbird/04-coturn-config.yaml <<EOF
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

# Create PersistentVolumeClaim
cat > k8s-manifests/netbird/05-storage.yaml <<EOF
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

# Create Management Deployment
cat > k8s-manifests/netbird/06-management-deployment.yaml <<EOF
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

# Create Signal Deployment
cat > k8s-manifests/netbird/07-signal-deployment.yaml <<EOF
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

# Create Relay Deployment
cat > k8s-manifests/netbird/08-relay-deployment.yaml <<EOF
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

# Create Dashboard Deployment
cat > k8s-manifests/netbird/09-dashboard-deployment.yaml <<EOF
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

# Create Coturn Deployment
cat > k8s-manifests/netbird/10-coturn-deployment.yaml <<EOF
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

# Create NetBird deployment script
cat > k8s-manifests/netbird/deploy.sh <<'DEPLOYEOF'
#!/bin/bash
set -e

NAMESPACE="netbird"

echo "🚀 Deploying NetBird to Kubernetes..."

# Apply manifests in order
kubectl apply -f 01-management-config.yaml
kubectl apply -f 02-dashboard-config.yaml
kubectl apply -f 03-relay-config.yaml
kubectl apply -f 04-coturn-config.yaml
kubectl apply -f 05-storage.yaml
kubectl apply -f 06-management-deployment.yaml
kubectl apply -f 07-signal-deployment.yaml
kubectl apply -f 08-relay-deployment.yaml
kubectl apply -f 09-dashboard-deployment.yaml
kubectl apply -f 10-coturn-deployment.yaml

echo "✅ NetBird deployed successfully!"
echo ""
echo "📊 Check deployment status:"
echo "  kubectl get pods -n $NAMESPACE"
echo ""
echo "🔍 View logs:"
echo "  kubectl logs -n $NAMESPACE -l app=netbird-management"
DEPLOYEOF

chmod +x k8s-manifests/netbird/deploy.sh

echo "✅ All NetBird Kubernetes manifests generated"

echo ""
echo "════════════════════════════════════════════════════"
echo "🚀 STEP 6: Deploying NetBird"
echo "════════════════════════════════════════════════════"
echo ""

# Deploy NetBird
cd k8s-manifests/netbird
./deploy.sh
cd ../..

echo ""
echo "════════════════════════════════════════════════════"
echo "✅ COMPLETE SETUP FINISHED!"
echo "════════════════════════════════════════════════════"
echo ""
echo "📋 ZITADEL CONFIGURATION:"
echo "────────────────────────────────────────────────────"
echo "Zitadel URL: $ZITADEL_BASE"
echo "Zitadel PAT: $ZITADEL_PAT"
echo "PostgreSQL Password: $POSTGRES_PASSWORD"
echo "Zitadel Masterkey: $ZITADEL_MASTERKEY"
echo ""
echo "Project ID: $PROJECT_ID"
echo ""
echo "Dashboard (SPA):"
echo "  Client ID: $DASHBOARD_APP_ID"
echo ""
echo "CLI (SPA):"
echo "  Client ID: $CLI_APP_ID"
echo ""
echo "Service User:"
echo "  User ID: $SERVICE_USER_ID"
echo "  Client ID: $SERVICE_USER_CLIENT_ID"
echo "  Client Secret: $SERVICE_USER_CLIENT_SECRET"
echo "  Role: ORG_USER_MANAGER"
echo ""
echo "Admin User:"
echo "  User ID: $ADMIN_USER_ID"
echo "  Email: $ADMIN_EMAIL"
echo "  Username: $ADMIN_USERNAME"
echo "  Temporary Password: TempPassword123!"
echo "  Roles: ORG_OWNER, IAM_OWNER"
echo ""
echo "📋 NETBIRD CONFIGURATION:"
echo "────────────────────────────────────────────────────"
echo "TURN Password: $TURN_PASSWORD"
echo "TURN Secret: $TURN_SECRET"
echo "Relay Auth Secret: $RELAY_AUTH_SECRET"
echo ""
echo "📁 GENERATED FILES:"
echo "────────────────────────────────────────────────────"
echo "k8s-manifests/"
echo "├── zitadel/"
echo "│   └── zitadel-all.yaml"
echo "└── netbird/"
echo "    ├── 01-management-config.yaml"
echo "    ├── 02-dashboard-config.yaml"
echo "    ├── 03-relay-config.yaml"
echo "    ├── 04-coturn-config.yaml"
echo "    ├── 05-storage.yaml"
echo "    ├── 06-management-deployment.yaml"
echo "    ├── 07-signal-deployment.yaml"
echo "    ├── 08-relay-deployment.yaml"
echo "    ├── 09-dashboard-deployment.yaml"
echo "    ├── 10-coturn-deployment.yaml"
echo "    └── deploy.sh"
echo ""
echo "🚀 NEXT STEPS:"
echo "────────────────────────────────────────────────────"
echo "1. Monitor deployment:"
echo "   kubectl get pods -n $NAMESPACE -w"
echo ""
echo "2. Access Zitadel:"
echo "   $ZITADEL_BASE"
echo "   Username: zitadel-admin"
echo "   Password: $POSTGRES_PASSWORD"
echo ""
echo "3. Access NetBird:"
echo "   https://$NETBIRD_DOMAIN"
echo "   Login with admin credentials: $ADMIN_EMAIL"
echo "   Temporary Password: TempPassword123!"
echo ""
echo "4. Configure DNS:"
echo "   zitadel.$BASE_DOMAIN → Your Kubernetes Ingress IP"
echo "   netbird.$BASE_DOMAIN → Your Kubernetes Ingress IP"
echo "   stun.$NETBIRD_DOMAIN → Your Kubernetes Node IP (for Coturn)"
echo ""
echo "════════════════════════════════════════════════════"

# Save configuration to file
cat > k8s-manifests/SETUP_INFO.txt <<EOF
NetBird + Zitadel Setup Configuration
Generated: $(date)
════════════════════════════════════════════════════

ZITADEL:
--------
URL: $ZITADEL_BASE
Admin Username: zitadel-admin
Admin Password: $POSTGRES_PASSWORD
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
URL: https://$NETBIRD_DOMAIN
Admin Email: $ADMIN_EMAIL
Admin Username: $ADMIN_USERNAME
Temporary Password: TempPassword123!
Admin User ID: $ADMIN_USER_ID

TURN Password: $TURN_PASSWORD
TURN Secret: $TURN_SECRET
Relay Auth Secret: $RELAY_AUTH_SECRET

DNS CONFIGURATION:
------------------
zitadel.$BASE_DOMAIN → Kubernetes Ingress IP
netbird.$BASE_DOMAIN → Kubernetes Ingress IP
stun.$NETBIRD_DOMAIN → Kubernetes Node IP

IMPORTANT:
----------
1. Change the admin password after first login to NetBird
2. Configure your DNS records as shown above
3. Ensure your ingress controller is configured with SSL/TLS
4. Keep this file secure - it contains sensitive credentials
EOF

echo "💾 Configuration saved to: k8s-manifests/SETUP_INFO.txt"
echo ""