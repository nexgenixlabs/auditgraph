#!/usr/bin/env python3
"""Test AuditGraph Discovery Engine"""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.engines.discovery import AzureDiscoveryEngine
import json
from datetime import datetime


def main():
    print("\n" + "="*70)
    print(" "*20 + "AuditGraph Discovery Test")
    print("="*70)
    
    required_vars = ['AZURE_TENANT_ID', 'AZURE_CLIENT_ID', 'AZURE_CLIENT_SECRET', 'AZURE_SUBSCRIPTION_ID']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        print("\n❌ Missing environment variables:")
        for var in missing_vars:
            print(f"   - {var}")
        sys.exit(1)
    
    print("\n✓ Environment variables loaded")
    
    try:
        engine = AzureDiscoveryEngine()
        result = engine.run_discovery()
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = f"discovery_results_{timestamp}.json"
        
        with open(output_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
        
        print(f"✓ Results saved to: {output_file}\n")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
