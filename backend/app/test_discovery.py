"""
AuditGraph Discovery Test Runner

Runs Azure + Entra discovery and stores results as a new discovery run in the DB.
"""

import os
import sys
from dotenv import load_dotenv

# Ensure app module is resolvable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engines.discovery.azure_discovery import AzureDiscoveryEngine


def main():
    print("=" * 70)
    print("                    AuditGraph Discovery Test")
    print("=" * 70)

    # Load environment variables from backend/.env
    load_dotenv()
    print("✓ Environment variables loaded")

    # Required Azure credentials
    tenant_id = os.getenv("AZURE_TENANT_ID")
    client_id = os.getenv("AZURE_CLIENT_ID")
    client_secret = os.getenv("AZURE_CLIENT_SECRET")

    # Optional (engine may use it internally)
    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

    # Validate env vars
    missing = []
    if not tenant_id:
        missing.append("AZURE_TENANT_ID")
    if not client_id:
        missing.append("AZURE_CLIENT_ID")
    if not client_secret:
        missing.append("AZURE_CLIENT_SECRET")

    if missing:
        raise Exception(f"❌ Missing required environment variables: {', '.join(missing)}")

    print("✓ Azure credentials found")
    if subscription_id:
        print(f"✓ Subscription ID (env): {subscription_id}")

    try:
        # Initialize discovery engine (NOTE: subscription_id is NOT a constructor arg)
        engine = AzureDiscoveryEngine(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )

        print("✓ AzureDiscoveryEngine initialized")
        print("▶ Starting discovery run...")

        # Run discovery
        engine.run_discovery()

        print("✓ Discovery completed successfully")

    except Exception:
        print("❌ Discovery failed")
        raise


if __name__ == "__main__":
    main()
