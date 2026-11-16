import os
import streamlit as st
from azure.identity import ClientSecretCredential, AzureCliCredential

def get_secret(name):
    try:
        if name in st.secrets:
            return st.secrets[name]
    except Exception:
        pass
    return os.getenv(name)

client_id = get_secret("AZURE_CLIENT_ID")
client_secret = get_secret("AZURE_CLIENT_SECRET")
tenant_id = get_secret("AZURE_TENANT_ID")

if client_id and client_secret and tenant_id:
    credential = ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=client_secret,
    )
else:
    credential = AzureCliCredential()