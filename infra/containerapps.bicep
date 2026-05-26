// ─────────────────────────────────────────────────────────────────────────────
// AuditGraph Dev Environment — Azure Container Apps
//
// Deploys 3 container apps into an existing Container Apps Environment:
//   - auditgraph-api-dev   (backend API, port 8000)
//   - auditgraph-app-dev   (client portal, port 3000)
//   - auditgraph-admin-dev (admin portal, port 3001)
//
// Usage:
//   az deployment group create \
//     --resource-group cus-ag-nonprod-rg \
//     --template-file infra/containerapps.bicep \
//     --parameters dbPassword='...' dbAdminPassword='...' jwtSecret='...' \
//                  adminJwtSecret='...' clientJwtSecret='...'
// ─────────────────────────────────────────────────────────────────────────────

// ── Parameters ──────────────────────────────────────────────────────────────

@description('Name of the existing Container Apps Environment')
param environmentName string = 'dev-cae'

@description('Azure Container Registry login server')
param acrLoginServer string = 'cusagnonprodcr.azurecr.io'

@description('API container image tag')
param apiImageTag string = 'dev'

@description('App container image tag')
param appImageTag string = 'dev'

@description('Admin container image tag')
param adminImageTag string = 'dev'

@description('PostgreSQL host')
param dbHost string = 'cus-ag-nonprod-pg.postgres.database.azure.com'

@description('PostgreSQL database name')
param dbName string = 'auditgraph_dev_eastus2'

@description('PostgreSQL app user')
param dbUser string = 'auditgraph_app'

@secure()
@description('PostgreSQL app user password')
param dbPassword string

@description('PostgreSQL admin user')
param dbAdminUser string = 'auditgraph_admin'

@secure()
@description('PostgreSQL admin user password')
param dbAdminPassword string

@secure()
@description('JWT signing secret (dev fallback)')
param jwtSecret string

@secure()
@description('Admin portal JWT secret')
param adminJwtSecret string

@secure()
@description('Client portal JWT secret')
param clientJwtSecret string

@description('CORS allowed origins (comma-separated)')
param corsOrigins string = 'https://dev.app.auditgraph.ai,https://dev.admin.auditgraph.ai,https://demo.auditgraph.ai'

@description('Maximum DB connection pool size per replica')
param dbPoolMax int = 8

// ── Existing Environment Reference ─────────────────────────────────────────

resource cae 'Microsoft.App/managedEnvironments@2024-03-01' existing = {
  name: environmentName
}

// ── API Container App ───────────────────────────────────────────────────────

resource apiApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-api-dev'
  location: resourceGroup().location
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
          identity: 'system'
        }
      ]
      secrets: [
        { name: 'db-password', value: dbPassword }
        { name: 'db-admin-password', value: dbAdminPassword }
        { name: 'jwt-secret', value: jwtSecret }
        { name: 'admin-jwt-secret', value: adminJwtSecret }
        { name: 'client-jwt-secret', value: clientJwtSecret }
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
            { name: 'ALLOWED_ORIGINS', value: corsOrigins }
            { name: 'ALLOW_DEMO', value: 'true' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: {
                path: '/api/health'
                port: 8000
              }
              initialDelaySeconds: 15
              periodSeconds: 30
              failureThreshold: 3
            }
            {
              type: 'Readiness'
              httpGet: {
                path: '/api/health'
                port: 8000
              }
              initialDelaySeconds: 10
              periodSeconds: 10
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
  identity: {
    type: 'SystemAssigned'
  }
}

// ── Client App Container App ────────────────────────────────────────────────

resource clientApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-app-dev'
  location: resourceGroup().location
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
          identity: 'system'
        }
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
  identity: {
    type: 'SystemAssigned'
  }
}

// ── Admin App Container App ─────────────────────────────────────────────────

resource adminApp 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'auditgraph-admin-dev'
  location: resourceGroup().location
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
          identity: 'system'
        }
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
  identity: {
    type: 'SystemAssigned'
  }
}

// ── Outputs ─────────────────────────────────────────────────────────────────

output apiFqdn string = apiApp.properties.configuration.ingress.fqdn
output appFqdn string = clientApp.properties.configuration.ingress.fqdn
output adminFqdn string = adminApp.properties.configuration.ingress.fqdn
output apiPrincipalId string = apiApp.identity.principalId
