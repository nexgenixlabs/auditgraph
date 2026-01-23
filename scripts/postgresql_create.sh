# Use Central US for PostgreSQL
RESOURCE_GROUP="auditgraph-dev-rg"
LOCATION="centralus"
SERVER_NAME="auditgraph-db-dev"
ADMIN_USER="auditgraph_admin"
ADMIN_PASSWORD="AuditGraph2024!Secure"
DATABASE_NAME="auditgraph"

# Create PostgreSQL Flexible Server in Central US
az postgres flexible-server create \
  --resource-group $RESOURCE_GROUP \
  --name $SERVER_NAME \
  --location $LOCATION \
  --admin-user $ADMIN_USER \
  --admin-password $ADMIN_PASSWORD \
  --sku-name Standard_B1ms \
  --tier Burstable \
  --version 14 \
  --storage-size 32 \
  --public-access 0.0.0.0 \
  --yes

echo "✓ PostgreSQL server created: $SERVER_NAME.postgres.database.azure.com"