# AWS Deployment Guide

## Overview

This guide covers deploying the API Gateway + Backend + Keycloak stack to AWS. The architecture uses containerized services with managed AWS infrastructure.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              AWS CLOUD                                           │
│                                                                                  │
│  ┌─────────────┐     ┌─────────────────────────────────────────────────────┐    │
│  │   Route 53  │────▶│              Application Load Balancer              │    │
│  │   (DNS)     │     │                  (HTTPS:443)                        │    │
│  └─────────────┘     └─────────────────────────────────────────────────────┘    │
│                                          │                                       │
│                           ┌──────────────┼──────────────┐                       │
│                           │              │              │                       │
│                           ▼              ▼              ▼                       │
│                    ┌──────────┐   ┌──────────┐   ┌──────────┐                  │
│                    │ Gateway  │   │ Backend  │   │ Keycloak │                  │
│                    │ (ECS)    │   │ (ECS)    │   │ (ECS)    │                  │
│                    └──────────┘   └──────────┘   └──────────┘                  │
│                                          │              │                       │
│                                          ▼              ▼                       │
│                                   ┌─────────────────────────┐                   │
│                                   │      RDS PostgreSQL     │                   │
│                                   │      (Multi-AZ)         │                   │
│                                   └─────────────────────────┘                   │
│                                                                                  │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                       │
│  │    ECR      │     │  Secrets    │     │ CloudWatch  │                       │
│  │ (Images)    │     │  Manager    │     │  (Logs)     │                       │
│  └─────────────┘     └─────────────┘     └─────────────┘                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## AWS Services Required

| Service | Purpose | Tier Recommendation |
|---------|---------|---------------------|
| **ECR** | Container registry for Docker images | Standard |
| **ECS Fargate** | Serverless container orchestration | Fargate |
| **ALB** | Load balancer with HTTPS termination | Application LB |
| **RDS PostgreSQL** | Managed database for Keycloak | db.t3.medium |
| **Secrets Manager** | Store sensitive credentials | Standard |
| **Route 53** | DNS management | Standard |
| **ACM** | SSL/TLS certificates | Free with ALB |
| **CloudWatch** | Logging and monitoring | Standard |
| **VPC** | Network isolation | Custom VPC |

---

## Required Configuration Changes

### 1. Gateway - `nginx.conf`

#### Update CORS Origins

```nginx
# BEFORE (localhost only)
if ($http_origin ~* "^http://localhost:(5173|5174|3000|8080)$") {
    set $cors_origin $http_origin;
}

# AFTER (add production domains)
if ($http_origin ~* "^https://(www\.)?yourdomain\.com$") {
    set $cors_origin $http_origin;
}

if ($http_origin ~* "^https://app\.yourdomain\.com$") {
    set $cors_origin $http_origin;
}

# Keep localhost for development
if ($http_origin ~* "^http://localhost:(5173|5174|3000|8080)$") {
    set $cors_origin $http_origin;
}
```

#### Update DNS Resolver

```nginx
# BEFORE (Docker internal DNS)
resolver 127.0.0.11 valid=30s ipv6=off;

# AFTER (AWS VPC DNS)
resolver 169.254.169.253 valid=30s ipv6=off;
# OR use AWS-provided DNS:
resolver 10.0.0.2 valid=30s ipv6=off;  # VPC CIDR + 2
```

#### Update Upstream (ECS Service Discovery)

```nginx
# BEFORE
upstream backend_service {
    server backend:8000;
}

# AFTER (using AWS Cloud Map service discovery)
upstream backend_service {
    server backend.local:8000;  # Cloud Map namespace
}

# OR using ALB internal DNS
upstream backend_service {
    server internal-backend-alb-xxx.region.elb.amazonaws.com:8000;
}
```

---

### 2. Gateway - `lua/jwt_validator.lua`

#### Update JWKS URL and Issuers

```lua
-- BEFORE
local JWKS_URL = "http://keycloak:8080/realms/auth-realm/protocol/openid-connect/certs"

local EXPECTED_ISSUERS = {
    ["http://keycloak:8080/realms/auth-realm"] = true,
    ["http://localhost:8080/realms/auth-realm"] = true,
}

-- AFTER
local JWKS_URL = os.getenv("JWKS_URL") or "https://auth.yourdomain.com/realms/auth-realm/protocol/openid-connect/certs"

local EXPECTED_ISSUERS = {
    ["https://auth.yourdomain.com/realms/auth-realm"] = true,
    -- Internal ECS service discovery (if needed)
    ["http://keycloak.local:8080/realms/auth-realm"] = true,
}
```

#### Add Environment Variable Support

Create `gateway/lua/config.lua`:
```lua
local _M = {}

_M.JWKS_URL = os.getenv("JWKS_URL") or "https://auth.yourdomain.com/realms/auth-realm/protocol/openid-connect/certs"
_M.KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM") or "auth-realm"

_M.EXPECTED_ISSUERS = {}
local issuers = os.getenv("EXPECTED_ISSUERS") or "https://auth.yourdomain.com/realms/auth-realm"
for issuer in issuers:gmatch("[^,]+") do
    _M.EXPECTED_ISSUERS[issuer:match("^%s*(.-)%s*$")] = true
end

return _M
```

---

### 3. Backend - `app/core/config.py`

#### Add Production Settings

```python
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    ENV: str = "dev"

    KEYCLOAK_CLIENT_ID: str
    KEYCLOAK_CLIENT_SECRET: str
    KEYCLOAK_REALM: str
    KEYCLOAK_SERVER_URL: str = "http://localhost:8080"
    
    # NEW: External Keycloak URL for browser redirects
    KEYCLOAK_EXTERNAL_URL: str | None = None

    KEYCLOAK_ADMIN_CLIENT_ID: str | None = None
    KEYCLOAK_ADMIN_CLIENT_SECRET: str | None = None

    FRONTEND_URL: str = "http://localhost:5173"
    GATEWAY_URL: str = "http://localhost"
    
    # NEW: AWS-specific settings
    AWS_REGION: str = "ap-south-1"
    LOG_LEVEL: str = "INFO"
    
    # NEW: Health check path for ALB
    HEALTH_CHECK_PATH: str = "/health"

    @property
    def metadata_url(self) -> str:
        base_url = self.KEYCLOAK_EXTERNAL_URL or self.KEYCLOAK_SERVER_URL
        return (
            f"{base_url}/realms/"
            f"{self.KEYCLOAK_REALM}/.well-known/openid-configuration"
        )
    
    @property
    def is_production(self) -> bool:
        return self.ENV == "prod"


settings = Settings()
```

---

### 4. Backend - `Dockerfile`

#### Production-Optimized Dockerfile

```dockerfile
# Build stage
FROM python:3.10-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.10-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser

# Copy application code
COPY --chown=appuser:appuser . .

USER appuser

EXPOSE 8000

# Health check for ECS/ALB
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production command with proper settings
CMD ["gunicorn", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", \
     "app.main:app", "--bind", "0.0.0.0:8000", \
     "--forwarded-allow-ips", "*", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
```

---

### 5. Gateway - `Dockerfile`

#### Production Gateway Dockerfile

```dockerfile
FROM openresty/openresty:alpine-fat

# Install Lua dependencies
RUN opm get ledgetech/lua-resty-http \
    && opm get jkeys089/lua-resty-hmac \
    && opm get openresty/lua-resty-string \
    && opm get cdbattags/lua-resty-jwt \
    && opm get openresty/lua-resty-limit-traffic

# Install curl for health checks
RUN apk add --no-cache curl

# Copy configuration
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua/ /usr/local/openresty/nginx/lua/

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

EXPOSE 80

CMD ["openresty", "-g", "daemon off;"]
```

---

## AWS Infrastructure Setup

### 1. Create ECR Repositories

```bash
# Create repositories
aws ecr create-repository --repository-name as03/backend --region ap-south-1
aws ecr create-repository --repository-name as03/gateway --region ap-south-1
aws ecr create-repository --repository-name as03/keycloak --region ap-south-1

# Get login token
aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com
```

### 2. Build and Push Images

```bash
# Backend
docker build -t as03/backend .
docker tag as03/backend:latest <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/as03/backend:latest
docker push <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/as03/backend:latest

# Gateway
cd gateway
docker build -t as03/gateway .
docker tag as03/gateway:latest <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/as03/gateway:latest
docker push <ACCOUNT_ID>.dkr.ecr.ap-south-1.amazonaws.com/as03/gateway:latest
```

### 3. Create Secrets in AWS Secrets Manager

```bash
aws secretsmanager create-secret \
    --name as03/keycloak-credentials \
    --secret-string '{
        "KEYCLOAK_CLIENT_ID": "your-client-id",
        "KEYCLOAK_CLIENT_SECRET": "your-client-secret",
        "KEYCLOAK_ADMIN_CLIENT_ID": "admin-cli",
        "KEYCLOAK_ADMIN_CLIENT_SECRET": "your-admin-secret",
        "KC_DB_PASSWORD": "your-db-password"
    }'
```

### 4. RDS PostgreSQL Setup

```bash
aws rds create-db-instance \
    --db-instance-identifier keycloak-db \
    --db-instance-class db.t3.medium \
    --engine postgres \
    --engine-version 15 \
    --master-username keycloak \
    --master-user-password <PASSWORD> \
    --allocated-storage 20 \
    --vpc-security-group-ids sg-xxx \
    --db-subnet-group-name my-subnet-group \
    --multi-az \
    --storage-encrypted
```

---

## ECS Task Definitions

### Backend Task Definition

```json
{
  "family": "as03-backend",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "backend",
      "image": "<ACCOUNT>.dkr.ecr.ap-south-1.amazonaws.com/as03/backend:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "ENV", "value": "prod"},
        {"name": "KEYCLOAK_SERVER_URL", "value": "http://keycloak.local:8080"},
        {"name": "KEYCLOAK_EXTERNAL_URL", "value": "https://auth.yourdomain.com"},
        {"name": "KEYCLOAK_REALM", "value": "auth-realm"},
        {"name": "FRONTEND_URL", "value": "https://app.yourdomain.com"},
        {"name": "GATEWAY_URL", "value": "https://api.yourdomain.com"}
      ],
      "secrets": [
        {
          "name": "KEYCLOAK_CLIENT_ID",
          "valueFrom": "arn:aws:secretsmanager:ap-south-1:ACCOUNT:secret:as03/keycloak-credentials:KEYCLOAK_CLIENT_ID::"
        },
        {
          "name": "KEYCLOAK_CLIENT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:ap-south-1:ACCOUNT:secret:as03/keycloak-credentials:KEYCLOAK_CLIENT_SECRET::"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/as03-backend",
          "awslogs-region": "ap-south-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8000/health || exit 1"],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Gateway Task Definition

```json
{
  "family": "as03-gateway",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "gateway",
      "image": "<ACCOUNT>.dkr.ecr.ap-south-1.amazonaws.com/as03/gateway:latest",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 80,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "JWKS_URL", "value": "https://auth.yourdomain.com/realms/auth-realm/protocol/openid-connect/certs"},
        {"name": "EXPECTED_ISSUERS", "value": "https://auth.yourdomain.com/realms/auth-realm"}
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/as03-gateway",
          "awslogs-region": "ap-south-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

### Keycloak Task Definition

```json
{
  "family": "as03-keycloak",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "1024",
  "memory": "2048",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "keycloak",
      "image": "quay.io/keycloak/keycloak:24.0.1",
      "essential": true,
      "command": ["start", "--optimized"],
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {"name": "KC_DB", "value": "postgres"},
        {"name": "KC_DB_URL", "value": "jdbc:postgresql://keycloak-db.xxx.ap-south-1.rds.amazonaws.com:5432/keycloak"},
        {"name": "KC_DB_USERNAME", "value": "keycloak"},
        {"name": "KC_HOSTNAME", "value": "auth.yourdomain.com"},
        {"name": "KC_HOSTNAME_STRICT", "value": "true"},
        {"name": "KC_PROXY", "value": "edge"},
        {"name": "KC_HTTP_ENABLED", "value": "true"}
      ],
      "secrets": [
        {
          "name": "KC_DB_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:ap-south-1:ACCOUNT:secret:as03/keycloak-credentials:KC_DB_PASSWORD::"
        },
        {
          "name": "KEYCLOAK_ADMIN",
          "valueFrom": "arn:aws:secretsmanager:ap-south-1:ACCOUNT:secret:as03/keycloak-credentials:KEYCLOAK_ADMIN::"
        },
        {
          "name": "KEYCLOAK_ADMIN_PASSWORD",
          "valueFrom": "arn:aws:secretsmanager:ap-south-1:ACCOUNT:secret:as03/keycloak-credentials:KEYCLOAK_ADMIN_PASSWORD::"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/as03-keycloak",
          "awslogs-region": "ap-south-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

---

## ALB Configuration

### Target Groups

| Name | Port | Protocol | Health Check |
|------|------|----------|--------------|
| `tg-gateway` | 80 | HTTP | `/health` |
| `tg-backend` | 8000 | HTTP | `/health` |
| `tg-keycloak` | 8080 | HTTP | `/health` |

### Listener Rules

```
HTTPS:443
├── Host: api.yourdomain.com → tg-gateway
├── Host: auth.yourdomain.com → tg-keycloak
└── Default → 404
```

### Security Groups

```
ALB Security Group (sg-alb)
├── Inbound: 443 from 0.0.0.0/0
├── Inbound: 80 from 0.0.0.0/0 (redirect to HTTPS)
└── Outbound: All to VPC CIDR

ECS Security Group (sg-ecs)
├── Inbound: 80 from sg-alb
├── Inbound: 8000 from sg-alb
├── Inbound: 8080 from sg-alb
├── Inbound: All from sg-ecs (service-to-service)
└── Outbound: All

RDS Security Group (sg-rds)
├── Inbound: 5432 from sg-ecs
└── Outbound: None
```

---

## Environment Variables Summary

### Backend Service

| Variable | Production Value | Description |
|----------|------------------|-------------|
| `ENV` | `prod` | Environment mode |
| `KEYCLOAK_SERVER_URL` | `http://keycloak.local:8080` | Internal service URL |
| `KEYCLOAK_EXTERNAL_URL` | `https://auth.yourdomain.com` | Public Keycloak URL |
| `KEYCLOAK_REALM` | `auth-realm` | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | `(from secrets)` | OAuth client ID |
| `KEYCLOAK_CLIENT_SECRET` | `(from secrets)` | OAuth client secret |
| `FRONTEND_URL` | `https://app.yourdomain.com` | Frontend application URL |
| `GATEWAY_URL` | `https://api.yourdomain.com` | API gateway URL |

### Gateway Service

| Variable | Production Value | Description |
|----------|------------------|-------------|
| `JWKS_URL` | `https://auth.yourdomain.com/realms/auth-realm/protocol/openid-connect/certs` | JWKS endpoint |
| `EXPECTED_ISSUERS` | `https://auth.yourdomain.com/realms/auth-realm` | Comma-separated issuers |

### Keycloak Service

| Variable | Production Value | Description |
|----------|------------------|-------------|
| `KC_DB` | `postgres` | Database type |
| `KC_DB_URL` | `jdbc:postgresql://keycloak-db.xxx.rds.amazonaws.com:5432/keycloak` | RDS connection |
| `KC_HOSTNAME` | `auth.yourdomain.com` | Public hostname |
| `KC_PROXY` | `edge` | Behind ALB/reverse proxy |

---

## CI/CD Pipeline (GitHub Actions)

Create `.github/workflows/deploy.yml`:

```yaml
name: Deploy to AWS

on:
  push:
    branches: [main]

env:
  AWS_REGION: ap-south-1
  ECR_REGISTRY: ${{ secrets.AWS_ACCOUNT_ID }}.dkr.ecr.ap-south-1.amazonaws.com

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: ${{ env.AWS_REGION }}
      
      - name: Login to Amazon ECR
        id: login-ecr
        uses: aws-actions/amazon-ecr-login@v2
      
      - name: Build and push Backend
        run: |
          docker build -t $ECR_REGISTRY/as03/backend:${{ github.sha }} .
          docker push $ECR_REGISTRY/as03/backend:${{ github.sha }}
          docker tag $ECR_REGISTRY/as03/backend:${{ github.sha }} $ECR_REGISTRY/as03/backend:latest
          docker push $ECR_REGISTRY/as03/backend:latest
      
      - name: Build and push Gateway
        run: |
          docker build -t $ECR_REGISTRY/as03/gateway:${{ github.sha }} ./gateway
          docker push $ECR_REGISTRY/as03/gateway:${{ github.sha }}
          docker tag $ECR_REGISTRY/as03/gateway:${{ github.sha }} $ECR_REGISTRY/as03/gateway:latest
          docker push $ECR_REGISTRY/as03/gateway:latest
      
      - name: Update ECS services
        run: |
          aws ecs update-service --cluster as03-cluster --service backend-service --force-new-deployment
          aws ecs update-service --cluster as03-cluster --service gateway-service --force-new-deployment
```

---

## Deployment Checklist

### Pre-Deployment
- [ ] Create VPC with public/private subnets
- [ ] Set up NAT Gateway for private subnets
- [ ] Create RDS PostgreSQL instance
- [ ] Create ECR repositories
- [ ] Store secrets in AWS Secrets Manager
- [ ] Request SSL certificate in ACM
- [ ] Create ECS cluster

### Configuration Changes
- [ ] Update `nginx.conf` CORS origins
- [ ] Update `nginx.conf` DNS resolver
- [ ] Update `jwt_validator.lua` JWKS URL and issuers
- [ ] Update backend `config.py` with production URLs
- [ ] Create Cloud Map namespace for service discovery

### Deployment
- [ ] Build and push Docker images to ECR
- [ ] Create ECS task definitions
- [ ] Create ECS services
- [ ] Configure ALB target groups and listeners
- [ ] Set up Route 53 DNS records
- [ ] Verify health checks pass

### Post-Deployment
- [ ] Configure Keycloak realm and clients
- [ ] Update OAuth redirect URIs in Keycloak
- [ ] Test authentication flow end-to-end
- [ ] Set up CloudWatch alarms
- [ ] Configure auto-scaling policies

---

## Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| 401 Unauthorized | JWKS URL mismatch | Verify `JWKS_URL` matches Keycloak's external URL |
| 403 CORS Error | Missing allowed origin | Add production domain to `nginx.conf` |
| 502 Bad Gateway | Service discovery failure | Check Cloud Map namespace and ECS service registration |
| Keycloak redirect loop | `KC_PROXY` not set | Set `KC_PROXY=edge` for ALB termination |
| DB connection failed | Security group rules | Allow ECS SG → RDS SG on port 5432 |

### Useful Commands

```bash
# Check ECS service status
aws ecs describe-services --cluster as03-cluster --services backend-service

# View container logs
aws logs tail /ecs/as03-backend --follow

# Force new deployment
aws ecs update-service --cluster as03-cluster --service backend-service --force-new-deployment

# Check task health
aws ecs describe-tasks --cluster as03-cluster --tasks <TASK_ARN>
```

---

## Cost Estimation (ap-south-1)

| Service | Configuration | Monthly Cost (USD) |
|---------|---------------|-------------------|
| ECS Fargate | 3 tasks × 0.5 vCPU × 1GB | ~$35 |
| RDS PostgreSQL | db.t3.medium, Multi-AZ | ~$65 |
| ALB | 1 ALB + data transfer | ~$20 |
| NAT Gateway | 1 NAT + data transfer | ~$35 |
| ECR | 10GB storage | ~$1 |
| Secrets Manager | 3 secrets | ~$1.20 |
| CloudWatch Logs | 10GB/month | ~$5 |
| **Total** | | **~$162/month** |

> Costs vary based on traffic and data transfer. Use AWS Pricing Calculator for accurate estimates.
