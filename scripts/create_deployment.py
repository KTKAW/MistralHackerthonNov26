#!/usr/bin/env python3
"""Create Mistral Workflows deployment for le-chonk."""
import os
from mistralai.client import Mistral

MISTRAL_API_KEY = os.environ.get("MISTRAL_API_KEY")
DEPLOYMENT_NAME = os.environ.get("DEPLOYMENT_NAME", "le-chonk-demo")

if not MISTRAL_API_KEY:
    print("ERROR: MISTRAL_API_KEY environment variable is required")
    exit(1)

client = Mistral(api_key=MISTRAL_API_KEY)
print(f"Creating deployment '{DEPLOYMENT_NAME}'...")

try:
    # Create deployment spec with the workflow
    deployment = client.workflows.deployments.create_deployment(
        name=DEPLOYMENT_NAME,
        spec={
            "workflows": [
                {
                    "identifier": "le_chonk_run",
                    "entrypoint": "orchestrator.workflow:LeChonkRun"
                }
            ]
        }
    )
    print(f"✓ Deployment created: {deployment.name}")
    print(f"  Status: {deployment.status}")
    print(f"  Deployment ID: {deployment.id}")
except Exception as e:
    print(f"ERROR: Failed to create deployment: {e}")
    import traceback
    traceback.print_exc()
    exit(1)
