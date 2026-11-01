from azure.identity import AzureCliCredential
from azure.mgmt.storage import StorageManagementClient

# Azure subscription
SUBSCRIPTION_ID = "3295c2de-964f-43f0-8429-6ef55498e26d"

# Azure resource
RESOURCE_GROUP = "driftstore"
STORAGE_ACCOUNT = "clouddriftlab2026"

# Authenticate using Azure CLI
credential = AzureCliCredential()

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

# Extract the settings we want to monitor
current_state = {
    "allowBlobPublicAccess": properties["allowBlobPublicAccess"],
    "publicNetworkAccess": properties["publicNetworkAccess"],
    "minimumTlsVersion": properties["minimumTlsVersion"],
    "allowSharedKeyAccess": properties["allowSharedKeyAccess"],
    "supportsHttpsTrafficOnly": properties["supportsHttpsTrafficOnly"]
}

# Display current state
print("\n========== CURRENT AZURE STATE ==========")
print("Storage Account:", STORAGE_ACCOUNT)
print()

for setting, value in current_state.items():
    print(f"{setting}: {value}")

print("\n=========================================")