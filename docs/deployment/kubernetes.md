# Kubernetes Deployment

Deploy Egide on Kubernetes for enterprise scalability and high availability.

## Prerequisites

- Kubernetes 1.25+
- kubectl configured
- Helm 3.x (optional but recommended)

## Quick Start with Helm

### Add Repository

```bash
helm repo add nubster https://charts.nubster.com
helm repo update
```

### Install

```bash
helm install egide nubster/egide \
  --namespace egide \
  --create-namespace
```

### With Custom Values

```bash
helm install egide nubster/egide \
  --namespace egide \
  --create-namespace \
  --set replicas=3 \
  --set storage.type=postgresql \
  --set postgresql.enabled=true
```

## Manual Deployment

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: egide
  labels:
    app.kubernetes.io/name: egide
```

### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: egide-config
  namespace: egide
data:
  egide.toml: |
    [server]
    bind_address = "0.0.0.0:8200"

    [storage]
    type = "postgresql"

    [storage.postgresql]
    host = "egide-postgresql"
    port = 5432
    database = "egide"
    username = "egide"
    password_env = "EGIDE_DB_PASSWORD"

    [log]
    level = "info"
    format = "json"
```

### Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: egide-secrets
  namespace: egide
type: Opaque
stringData:
  db-password: "your-secure-password"
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: egide
  namespace: egide
  labels:
    app.kubernetes.io/name: egide
spec:
  replicas: 3
  selector:
    matchLabels:
      app.kubernetes.io/name: egide
  template:
    metadata:
      labels:
        app.kubernetes.io/name: egide
    spec:
      serviceAccountName: egide
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
        - name: egide
          image: nubster/egide:latest
          imagePullPolicy: Always
          ports:
            - name: http
              containerPort: 8200
              protocol: TCP
          env:
            - name: EGIDE_CONFIG
              value: /etc/egide/egide.toml
            - name: EGIDE_DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: egide-secrets
                  key: db-password
          volumeMounts:
            - name: config
              mountPath: /etc/egide
              readOnly: true
          livenessProbe:
            httpGet:
              path: /v1/sys/health
              port: 8200
            initialDelaySeconds: 30
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /v1/sys/health
              port: 8200
            initialDelaySeconds: 5
            periodSeconds: 5
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
      volumes:
        - name: config
          configMap:
            name: egide-config
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: egide
  namespace: egide
  labels:
    app.kubernetes.io/name: egide
spec:
  type: ClusterIP
  ports:
    - port: 8200
      targetPort: http
      protocol: TCP
      name: http
  selector:
    app.kubernetes.io/name: egide
```

### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: egide
  namespace: egide
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
spec:
  tls:
    - hosts:
        - egide.example.com
      secretName: egide-tls
  rules:
    - host: egide.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: egide
                port:
                  number: 8200
```

### ServiceAccount

```yaml
# serviceaccount.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: egide
  namespace: egide
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: egide-tokenreview
rules:
  - apiGroups: ["authentication.k8s.io"]
    resources: ["tokenreviews"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: egide-tokenreview
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: egide-tokenreview
subjects:
  - kind: ServiceAccount
    name: egide
    namespace: egide
```

## PostgreSQL (StatefulSet)

```yaml
# postgresql.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: egide-postgresql
  namespace: egide
spec:
  serviceName: egide-postgresql
  replicas: 1
  selector:
    matchLabels:
      app: egide-postgresql
  template:
    metadata:
      labels:
        app: egide-postgresql
    spec:
      containers:
        - name: postgresql
          image: postgres:16-alpine
          ports:
            - containerPort: 5432
          env:
            - name: POSTGRES_USER
              value: egide
            - name: POSTGRES_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: egide-secrets
                  key: db-password
            - name: POSTGRES_DB
              value: egide
          volumeMounts:
            - name: data
              mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
    - metadata:
        name: data
      spec:
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 10Gi
---
apiVersion: v1
kind: Service
metadata:
  name: egide-postgresql
  namespace: egide
spec:
  ports:
    - port: 5432
  selector:
    app: egide-postgresql
  clusterIP: None
```

## High Availability

### Pod Disruption Budget

```yaml
# pdb.yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: egide
  namespace: egide
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app.kubernetes.io/name: egide
```

### Pod Anti-Affinity

Add to deployment spec:

```yaml
spec:
  template:
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
            - weight: 100
              podAffinityTerm:
                labelSelector:
                  matchLabels:
                    app.kubernetes.io/name: egide
                topologyKey: kubernetes.io/hostname
```

### Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: egide
  namespace: egide
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: egide
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
```

## Operations

### Initialize

```bash
kubectl exec -it -n egide deploy/egide -- egide operator init
```

### Unseal

```bash
kubectl exec -it -n egide deploy/egide -- egide operator unseal
```

### View Logs

```bash
kubectl logs -n egide -l app.kubernetes.io/name=egide -f
```

### Port Forward (Debug)

```bash
kubectl port-forward -n egide svc/egide 8200:8200
```

## Helm Values Reference

```yaml
# values.yaml
replicaCount: 3

image:
  repository: nubster/egide
  tag: latest
  pullPolicy: Always

service:
  type: ClusterIP
  port: 8200

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: egide.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: egide-tls
      hosts:
        - egide.example.com

storage:
  type: postgresql

postgresql:
  enabled: true
  auth:
    username: egide
    password: ""  # Set via --set or secret
    database: egide
  primary:
    persistence:
      size: 10Gi

resources:
  requests:
    cpu: 100m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

## Next Steps

- [Binary Installation](./binary.md)
- [Production Checklist](./production-checklist.md)
- [Kubernetes Auth Method](../concepts/authentication.md#kubernetes)
