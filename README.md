# AuditGraph

**Cloud Identity Security Posture Management (CISPM)** - Discover, analyze, and govern human and non-human identities across cloud environments.

## Overview

AuditGraph is an enterprise-grade security platform that provides comprehensive visibility into cloud identity posture. It discovers and analyzes identities across Azure/Entra ID, calculates risk levels, and provides actionable insights for security teams.

### Key Features

- **Identity Discovery**: Automatically discover all identity types in your Azure tenant
  - Service Principals (customer-owned applications)
  - Managed Identities (System-assigned & User-assigned)
  - Human Users with Azure RBAC or Entra ID roles
  - Guest accounts
  - Microsoft Internal services (for visibility)

- **Risk Assessment**: Multi-factor risk calculation based on:
  - Azure RBAC role assignments (Owner, Contributor, User Access Administrator)
  - Entra ID directory roles (Global Administrator, Application Administrator)
  - Credential status and expiration
  - Orphaned/unused identities

- **Permission Analysis**: Deep inspection of identity permissions
  - Microsoft Graph API permissions
  - Custom application role assignments
  - Azure RBAC scope analysis (subscription, resource group, resource)

- **Credential Management**: Track and monitor identity credentials
  - Secrets with expiration dates
  - Certificates
  - Federated identity credentials

- **Dashboard & Reporting**: Clean, enterprise-ready UI
  - Risk-based identity overview
  - Category-based filtering
  - Drill-down identity details
  - Role intelligence with attack patterns

- **Scheduled Discovery & Change Alerts**: Automated monitoring with email notifications
  - Configurable discovery interval (6, 12, or 24 hours)
  - Email alerts when identities are added or removed
  - Summary table showing category changes (Before | After | Change)
  - Only sends notifications when actual changes occur (no spam)

## Architecture

```
auditgraph/
├── backend/                    # Python Flask REST API
│   ├── app/
│   │   ├── api/               # REST endpoints
│   │   ├── engines/           # Discovery engine
│   │   │   └── discovery/     # Azure/Entra discovery
│   │   └── database.py        # PostgreSQL data layer
│   └── migrations/            # Database schema
├── frontend/                   # React TypeScript UI
│   └── src/
│       ├── pages/             # Dashboard, Identities, Details
│       └── components/        # Reusable UI components
└── docs/                       # Documentation
```

## Identity Categories

AuditGraph categorizes discovered identities into distinct groups:

| Category | Description |
|----------|-------------|
| **Service Principal** | Customer-owned Azure AD applications |
| **System Assigned Identity** | Managed identities bound to Azure resource lifecycle |
| **User Assigned Identity** | Standalone managed identities for flexible assignment |
| **Human User** | Users with Azure RBAC or Entra directory roles |
| **Guest** | External/guest user accounts |
| **Microsoft Internal** | Microsoft first-party services (informational) |

## Risk Levels

| Level | Description | Examples |
|-------|-------------|----------|
| **Critical** | Highest privilege access | Subscription Owner/Contributor, Global Administrator |
| **High** | Significant privilege elevation | Security Administrator, User Access Administrator |
| **Medium** | Moderate risk | Reader roles, orphaned identities |
| **Low** | Minimal risk | Properly scoped, limited access |
| **Info** | No security concern | Microsoft internal services |

## Local Development

### Prerequisites

- Python 3.9+
- Node.js 18+
- PostgreSQL database (Azure Postgres Flexible Server or local)
- Azure Service Principal with read permissions

### Backend Setup

```bash
# Create virtual environment and install dependencies
make backend

# Configure environment
cp backend/.env.example backend/.env.local
# Edit backend/.env.local with your Azure and database credentials

# Run API server
make api
# API runs on http://localhost:5001
```

### Frontend Setup

```bash
# Install dependencies
make frontend

# Run development server
make ui
# UI runs on http://localhost:3000
```

### Environment Variables

Create `backend/.env.local` with:

```env
# Azure Service Principal (read-only recommended)
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret
AZURE_SUBSCRIPTION_ID=your-subscription-id

# PostgreSQL Database
DB_HOST=your-db-host
DB_PORT=5432
DB_NAME=auditgraph
DB_USER=your-db-user
DB_PASSWORD=your-db-password

# Email Notifications (Microsoft Graph API)
EMAIL_FROM=sender@yourdomain.com
EMAIL_TO=security-team@yourdomain.com

# Scheduler Configuration
DISCOVERY_INTERVAL_HOURS=12  # Options: 6, 12, or 24
```

## Scheduled Discovery

AuditGraph runs automated discovery on a configurable schedule and sends email notifications when identity changes are detected.

### How It Works

1. **Scheduled Runs**: Discovery runs automatically every 6, 12, or 24 hours (configurable)
2. **Change Detection**: Compares current run with previous run to detect:
   - New identities added to the environment
   - Identities removed from the environment
3. **Email Alerts**: Sends HTML email report only when changes occur

### Email Report Format

```
+------------------------------------------+
|  AuditGraph Identity Change Report       |
|  Run #15 vs Run #14                      |
+------------------------------------------+

Summary by Category
| Category                  | Before | After | Change |
|---------------------------|--------|-------|--------|
| Service Principals        |   13   |  12   |   -1   |
| Human Users               |    6   |   6   |    0   |
| Guest Users               |    1   |   0   |   -1   |
| Microsoft Internal        |  193   | 193   |    0   |

Removed Identities (2)
- spn-old-service (Service Principal) [MEDIUM]
- guest-user@external.com (Guest) [LOW]
```

### Identity Discovery Rules

| Identity Type | Discovery Rule |
|---------------|----------------|
| Service Principals | All discovered (including orphaned with no roles) |
| User Assigned Managed Identities | All discovered (including orphaned) |
| System Assigned Managed Identities | Only with RBAC roles assigned |
| Human Users | Only with Azure RBAC or Entra ID roles |
| Guest Users | Only with roles assigned |
| Microsoft Internal | All discovered (informational only)

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/health` | Health check |
| `GET /api/stats` | Dashboard summary statistics |
| `GET /api/identity-summary` | Category breakdown with risk counts |
| `GET /api/identities` | List all identities (supports filtering) |
| `GET /api/identities/:id` | Identity details with roles and permissions |
| `GET /api/risks` | Critical and high-risk identities |

## Security Considerations

- **Least Privilege**: Use a service principal with minimal read-only permissions for discovery
- **Secrets Management**: Never commit `.env.local` or any secrets to version control
- **Network Security**: Deploy backend behind appropriate network controls
- **Data Classification**: Identity data should be treated as sensitive

## Technology Stack

**Backend:**
- Python 3.9+
- Flask (REST API)
- Microsoft Graph SDK
- Azure Identity SDK
- PostgreSQL

**Frontend:**
- React 18
- TypeScript
- Tailwind CSS
- React Router

## License

Proprietary - All rights reserved.

---

Built with security-first principles for enterprise cloud identity management.
