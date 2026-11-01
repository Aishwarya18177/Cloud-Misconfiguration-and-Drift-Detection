# Cloud Misconfiguration and Drift Detection

A Python-based Azure security project that compares live resource
configurations with approved JSON baselines.

## Features

- Azure Storage Account configuration and security checks
- Network Security Group custom-rule drift detection
- Detection of unrestricted SSH, RDP, and all-port inbound rules
- SQLite finding history with OPEN and RESOLVED statuses
- Successful and failed scan history
- Streamlit dashboard

## Technologies

Python, Azure CLI, Azure SDK, SQLite, Pandas, Streamlit, and JSON.

## Running the Project

Install the packages in requirements.txt, authenticate with az login,
and configure the Azure subscription, resource names, and baselines.

Run these commands from the project root:

    python -m collector.comparator
    python -m collector.nsg_comparator
    python -m streamlit run dashboard/app.py

## Scope

NSG checks assess configured custom rules, not effective network
reachability. Dashboard refreshes do not save comparator scan records.
