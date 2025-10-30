#!/bin/bash
set -euo pipefail

# ==============================
# CONFIGURATION
# ==============================
ZITADEL_BASE="https://zitadel.ryvie.ovh"
NETBIRD_DOMAIN="netbird.ryvie.ovh"
NAMESPACE="netbird"

# From your Zitadel setup
DASHBOARD_CLIENT_ID="344491078444974611"
CLI_CLIENT_ID="344491079082508819"
SERVICE_USER_CLIENT_ID="netbird-service-account"
SERVICE_USER_CLIENT_SECRET="uj1J4ckJiBNWe4AgkIeHmmaPbDDLUF62zKBfYHBlMnW7QtlSiiMPQy0mmNJu6DNS"

# Generate secure random passwords
TURN_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
TURN_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
RELAY_AUTH_SECRET=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)

echo "🔧 Generating NetBird Kubernetes manifests..."

# Create output directory
mkdir -p k8s-manifests

# ==============================
# Create namespace
# ==============================
cat > k8s-manifests/00-namespace.yaml <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
EOF

echo "✅ Created 00-namespace.yaml"

# ==============================
# Create management.json ConfigMap
# ==============================
cat > k8s-manifests/01-management-config.yaml <<EOF
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
            "AuthAudience": "$DASHBOARD_CLIENT_ID",
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
                "Audience": "$CLI_CLIENT_ID",
                "ClientID": "$CLI_CLIENT_ID",
                "Scope": "openid"
            }
        },
        "PKCEAuthorizationFlow": {
            "ProviderConfig": {
                "Audience": "$CLI_CLIENT_ID",
                "ClientID": "$CLI_CLIENT_ID",
                "Scope": "openid profile email offline_access",
                "RedirectURLs": ["http://localhost:53000/", "http://localhost:54000/"]
            }
        }
    }
EOF

echo "✅ Created 01-management-config.yaml"

# ==============================
# Create Dashboard ConfigMap
# ==============================
cat > k8s-manifests/02-dashboard-config.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: netbird-dashboard-config
  namespace: $NAMESPACE
data:
  NETBIRD_MGMT_API_ENDPOINT: "https://$NETBIRD_DOMAIN"
  NETBIRD_MGMT_GRPC_API_ENDPOINT: "https://$NETBIRD_DOMAIN"
  AUTH_AUDIENCE: "$DASHBOARD_CLIENT_ID"
  AUTH_CLIENT_ID: "$DASHBOARD_CLIENT_ID"
  AUTH_AUTHORITY: "$ZITADEL_BASE"
  USE_AUTH0: "false"
  AUTH_SUPPORTED_SCOPES: "openid profile email offline_access"
  AUTH_REDIRECT_URI: "/nb-auth"
  AUTH_SILENT_REDIRECT_URI: "/nb-silent-auth"
  NGINX_SSL_PORT: "443"
  LETSENCRYPT_DOMAIN: "none"
EOF

echo "✅ Created 02-dashboard-config.yaml"

# ==============================
# Create Relay ConfigMap
# ==============================
cat > k8s-manifests/03-relay-config.yaml <<EOF
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

echo "✅ Created 03-relay-config.yaml"

# ==============================
# Create Coturn ConfigMap
# ==============================
cat > k8s-manifests/04-coturn-config.yaml <<EOF
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

echo "✅ Created 04-coturn-config.yaml"

# ==============================
# Create PersistentVolumeClaim
# ==============================
cat > k8s-manifests/05-storage.yaml <<EOF
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

echo "✅ Created 05-storage.yaml"

# ==============================
# Create Management Deployment
# ==============================
cat > k8s-manifests/06-management-deployment.yaml <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: netbird-management
  namespace: netbird
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
  namespace: netbird
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

echo "✅ Created 06-management-deployment.yaml"

# ==============================
# Create Signal Deployment
# ==============================
cat > k8s-manifests/07-signal-deployment.yaml <<EOF
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

echo "✅ Created 07-signal-deployment.yaml"

# ==============================
# Create Relay Deployment
# ==============================
cat > k8s-manifests/08-relay-deployment.yaml <<EOF
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

echo "✅ Created 08-relay-deployment.yaml"

# ==============================
# Create Dashboard Deployment
# ==============================
cat > k8s-manifests/09-dashboard-deployment.yaml <<EOF
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

echo "✅ Created 09-dashboard-deployment.yaml"

# ==============================
# Create Coturn Deployment
# ==============================
cat > k8s-manifests/10-coturn-deployment.yaml <<EOF
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

echo "✅ Created 10-coturn-deployment.yaml"

# ==============================
# Create deployment script
# ==============================
cat > k8s-manifests/deploy.sh <<'EOF'
#!/bin/bash
set -e

NAMESPACE="netbird"

echo "🚀 Deploying NetBird to Kubernetes..."

# Apply manifests in order
kubectl apply -f 00-namespace.yaml
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
echo ""
echo "🌐 Access NetBird:"
echo "  https://netbird.ryvie.ovh"
EOF

chmod +x k8s-manifests/deploy.sh

echo "✅ Created deploy.sh"

# ==============================
# Display generated credentials
# ==============================
echo ""
echo "════════════════════════════════════════════════════"
echo "✅ NetBird Kubernetes Configuration Complete!"
echo "════════════════════════════════════════════════════"
echo ""
echo "📁 Generated Kubernetes Manifests in: k8s-manifests/"
echo "  - 00-namespace.yaml"
echo "  - 01-management-config.yaml"
echo "  - 02-dashboard-config.yaml"
echo "  - 03-relay-config.yaml"
echo "  - 04-coturn-config.yaml"
echo "  - 05-storage.yaml"
echo "  - 06-management-deployment.yaml"
echo "  - 07-signal-deployment.yaml"
echo "  - 08-relay-deployment.yaml"
echo "  - 09-dashboard-deployment.yaml"
echo "  - 10-coturn-deployment.yaml"
echo "  - 11-ingress.yaml"
echo "  - deploy.sh"
echo ""
echo "🔑 Generated Credentials:"
echo "  TURN Password: $TURN_PASSWORD"
echo "  TURN Secret: $TURN_SECRET"
echo "  Relay Auth Secret: $RELAY_AUTH_SECRET"
echo ""
echo "🚀 Deploy to Kubernetes:"
echo "  cd k8s-manifests"
echo "  ./deploy.sh"
echo ""
echo "📊 Monitor deployment:"
echo "  kubectl get pods -n $NAMESPACE -w"
echo ""
echo "🌐 Access NetBird:"
echo "  https://$NETBIRD_DOMAIN"
echo ""
echo "════════════════════════════════════════════════════"