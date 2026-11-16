import os
import streamlit as st
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient

# Load Streamlit Secrets into environment variables (for Streamlit Cloud)
try:
    for key, value in st.secrets.items():
        if isinstance(value, str):
            os.environ[key] = value
except Exception:
    pass

# Azure subscription & resource
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "3295c2de-964f-43f0-8429-6ef55498e26d")
RESOURCE_GROUP = "driftstore"
STORAGE_ACCOUNT = "clouddriftlab2026"

# Authenticate (uses Service Principal in Streamlit Cloud, falls back to Azure CLI locally)
credential = DefaultAzureCredential()

# Connect to Azure Storage Management API
client = StorageManagementClient(
    credential,
    SUBSCRIPTION_ID
)

# Get current Azure configuration
account = client.storage_accounts.get_properties(
    RESOURCE_GROUP,
    STORAGE_ACCOUNT
)

# Azure SDK stores these settings inside "properties"
properties = account.as_dict()["properties"]

# Extract the settings we want to monitor (using .get() safely avoids KeyError if a property is unset)
current_state = {
    "allowBlobPublicAccess": properties.get("allowBlobPublicAccess"),
    "publicNetworkAccess": properties.get("publicNetworkAccess"),
    "minimumTlsVersion": properties.get("minimumTlsVersion"),
    "allowSharedKeyAccess": properties.get("allowSharedKeyAccess"),
    "supportsHttpsTrafficOnly": properties.get("supportsHttpsTrafficOnly")
}

# Display current state
print("\n========== CURRENT AZURE STATE ==========")
print("Storage Account:", STORAGE_ACCOUNT)
print()

for setting, value in current_state.items():
    print(f"{setting}: {value}")

print("\n=========================================")