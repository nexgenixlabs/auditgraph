// ─────────────────────────────────────────────────────────────────────────────
// AuditGraph DEV Environment — Azure Container Apps
//
// Deploys 3 container apps into an existing Container Apps Environment (dev-cae):
//   - auditgraph-api-dev   (backend API, port 8000, 1 CPU / 2Gi, 1–3 replicas)
//   - auditgraph-app-dev   (client portal, port 3000, 0.5 CPU / 1Gi)
//   - auditgraph-admin-dev (admin portal, port 3001, 0.5 CPU / 1Gi)
//
// All containers pull from ACR via admin credentials.
// ─────────────────────────────────────────────────────────────────────────────

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Existing Container Apps Environment name')
param environmentName string = 'dev-cae-ext'

@description('Azure Container Registry login server')
param acrLoginServer string = 'auditgraphcr.azurecr.io'

@secure()
@description('ACR admin username')
param acrUsername string

@secure()
@description('ACR admin password')
param acrPassword string

@description('API image tag')
param apiImageTag string = 'dev'

@description('Client app image tag')
param appImageTag string = 'dev'

@description('Admin app image tag')
param adminImageTag string = 'dev'

// ── Database Parameters ─────────────────────────────────────────────────────

@description('PostgreSQL Flexible Server FQDN (public hostname — resolves to private IP via VNet DNS)')
param dbHost string = 'cus-ag-nonprod-pg.postgres.database.azure.com'

@description('Database name')
param dbName string = 'auditgraph_dev_eastus2'

@description('Database app user (RLS-scoped)')
param dbUser string = 'auditgraph_dev_app'

@secure()
@description('Database app user password')
param dbPassword string

@description('Database admin user (BYPASSRLS)')
param dbAdminUser string = 'auditgraph_dev_admin'

@secure()
@description('Database admin user password')
param dbAdminPassword string

// ── JWT Secrets ─────────────────────────────────────────────────────────────

@secure()
@description('JWT signing secret')
param jwtSecret string

@secure()
@description('Admin portal JWT secret')
param adminJwtSecret string

@secure()
@description('Client portal JWT secret')
param clientJwtSecret string

// ── App Admin Bootstrap ───────────────────────────────────────────────────────

@secure()
@description('Admin user password (synced on every startup)')
param adminPassword string = ''

// ── Azure Discovery Credentials (for auto-seeding cloud connections) ────────

@description('Azure Entra Directory ID to monitor')
param azureDirectoryId string = ''

@description('Azure SP Client ID for discovery')
param azureClientId string = ''

@secure()
@description('Azure SP Client Secret for discovery')
param azureClientSecret string = ''

// ── Optional Parameters ─────────────────────────────────────────────────────

@description('CORS allowed origins')
param corsOrigins string = 'https://dev.app.auditgraph.ai,https://dev.admin.auditgraph.ai,https://demo.auditgraph.ai'

@description('Max DB pool connections per replica')
param dbPoolMax int = 8

// ── Existing Environment ────────────────────────────────────────────────────

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: environmentName
}

// ── Managed Certificates ──────────────────────────────────────────────────────
// Custom domains & certs are added AFTER initial deploy via az CLI:
//   az containerapp hostname add ...
//   az containerapp hostname bind --hostname ... --environment dev-cae-ext --validation-method CNAME
// Uncomment these once certificates exist:
// resource certApi 'Microsoft.App/managedEnvironments/managedCertificates@2024-03-01' existing = {
//   parent: cae
//   name: 'mc-dev-cae-ext-dev-api-auditgra-2025'
// }
// resource certApp 'Microsoft.App/managedEnvironments/managedCertificates@2024-03-01' existing = {
//   parent: cae
//   name: 'mc-dev-cae-ext-dev-app-auditgra-8561'
// }
// resource certAdmin 'Microsoft.App/managedEnvironments/managedCertificates@2024-03-01' existing = {
//   parent: cae
//   name: 'mc-dev-cae-ext-dev-admin-auditg-9679'
// }
// resource certDemo 'Microsoft.App/managedEnvironments/managedCertificates@2024-03-01' existing = {
//   parent: cae
//   name: 'mc-dev-cae-ext-demo-auditgraph'
// }

// ═════════════════════════════════════════════════════════════════════════════
// API Container App — auditgraph-api-dev
// ═════════════════════════════════════════════════════════════════════════════

resource apiApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-api-dev'
  location: 'centralus'
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 8000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        { name: 'acr-password', value: acrPassword }
        { name: 'db-password', value: dbPassword }
        { name: 'db-admin-password', value: dbAdminPassword }
        { name: 'jwt-secret', value: jwtSecret }
        { name: 'admin-jwt-secret', value: adminJwtSecret }
        { name: 'client-jwt-secret', value: clientJwtSecret }
        { name: 'admin-password', value: adminPassword }
        { name: 'azure-client-secret', value: empty(azureClientSecret) ? 'not-configured' : azureClientSecret }
      ]
    }
    template: {
      containers: [
        {
          name: 'api'
          image: '${acrLoginServer}/auditgraph-api:${apiImageTag}'
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          env: [
            { name: 'APP_ENV', value: 'dev' }
            { name: 'FLASK_ENV', value: 'production' }
            { name: 'PYTHONUNBUFFERED', value: '1' }
            { name: 'DB_HOST', value: dbHost }
            { name: 'DB_PORT', value: '5432' }
            { name: 'DB_NAME', value: dbName }
            { name: 'DB_USER', value: dbUser }
            { name: 'DB_PASSWORD', secretRef: 'db-password' }
            { name: 'DB_ADMIN_USER', value: dbAdminUser }
            { name: 'DB_ADMIN_PASSWORD', secretRef: 'db-admin-password' }
            { name: 'DB_SSLMODE', value: 'require' }
            { name: 'DB_POOL_MAX', value: string(dbPoolMax) }
            { name: 'JWT_SECRET', secretRef: 'jwt-secret' }
            { name: 'ADMIN_JWT_SECRET', secretRef: 'admin-jwt-secret' }
            { name: 'CLIENT_JWT_SECRET', secretRef: 'client-jwt-secret' }
            { name: 'ADMIN_PASSWORD', secretRef: 'admin-password' }
            { name: 'CORS_ORIGINS', value: corsOrigins }
            { name: 'ALLOW_DEMO', value: 'true' }
            { name: 'DEFAULT_ORG_SLUG', value: 'azurecredits' }
            { name: 'DEV_AZURE_DIRECTORY_ID', value: azureDirectoryId }
            { name: 'AZURE_TENANT_ID', value: azureDirectoryId }
            { name: 'AZURE_CLIENT_ID', value: azureClientId }
            { name: 'AZURE_CLIENT_SECRET', secretRef: 'azure-client-secret' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/health'
                port: 8000
              }
              initialDelaySeconds: 15
              periodSeconds: 30
              timeoutSeconds: 5
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/health/ready'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 10
              timeoutSeconds: 5
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 3
        rules: [
          {
            name: 'http-scaling'
            http: {
              metadata: {
                concurrentRequests: '50'
              }
            }
          }
        ]
      }
    }
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Client App — auditgraph-app-dev
// ═════════════════════════════════════════════════════════════════════════════

resource clientApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-app-dev'
  location: 'centralus'
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 3000
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        { name: 'acr-password', value: acrPassword }
      ]
    }
    template: {
      containers: [
        {
          name: 'app'
          image: '${acrLoginServer}/auditgraph-app:${appImageTag}'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/'
                port: 3000
              }
              initialDelaySeconds: 5
              periodSeconds: 30
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// Admin App — auditgraph-admin-dev
// ═════════════════════════════════════════════════════════════════════════════

resource adminApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-admin-dev'
  location: 'centralus'
  properties: {
    managedEnvironmentId: cae.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: true
        targetPort: 3001
        transport: 'auto'
        allowInsecure: false
      }
      registries: [
        {
          server: acrLoginServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: [
        { name: 'acr-password', value: acrPassword }
      ]
    }
    template: {
      containers: [
        {
          name: 'admin'
          image: '${acrLoginServer}/auditgraph-admin:${adminImageTag}'
          resources: {
            cpu: json('0.5')
            memory: '1Gi'
          }
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/'
                port: 3001
              }
              initialDelaySeconds: 5
              periodSeconds: 30
              failureThreshold: 3
            }
          ]
        }
      ]
      scale: {
        minReplicas: 1
        maxReplicas: 2
      }
    }
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output apiFqdn string = apiApp.properties.configuration.ingress.fqdn
output appFqdn string = clientApp.properties.configuration.ingress.fqdn
output adminFqdn string = adminApp.properties.configuration.ingress.fqdn
