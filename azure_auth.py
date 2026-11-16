import os
import streamlit as st
from azure.identity import ClientSecretCredential, AzureCliCredential

def get_azure_credential():
    def _secret(key):
        try:
            if key in st.secrets:
                return st.secrets[key]
        except Exception:
            pass
        return os.getenv(key)

    client_id = _secret("AZURE_CLIENT_ID")
    client_secret = _secret("AZURE_CLIENT_SECRET")
    tenant_id = _secret("AZURE_TENANT_ID")

    if client_id and client_secret and tenant_id:
        return ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    return AzureCliCredential()
