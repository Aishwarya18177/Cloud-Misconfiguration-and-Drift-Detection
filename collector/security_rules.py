def check_security_rules(actual_state, intended_state):
    findings = []

    # Rule 1: Blob public access
    if actual_state["allowBlobPublicAccess"] is True:
        findings.append({
            "setting": "allowBlobPublicAccess",
            "expected": intended_state["allowBlobPublicAccess"],
            "actual": actual_state["allowBlobPublicAccess"],
            "severity": "HIGH",
            "title": "Blob public access is enabled",
            "reason": (
                "The storage account allows containers "
                "to be configured for anonymous blob access."
            ),
            "recommendation": (
                "Disable Blob anonymous access unless "
                "public access is explicitly required."
            )
        })

    # Rule 2: HTTPS-only
    if actual_state["supportsHttpsTrafficOnly"] is False:
        findings.append({
            "setting": "supportsHttpsTrafficOnly",
            "expected": intended_state["supportsHttpsTrafficOnly"],
            "actual": actual_state["supportsHttpsTrafficOnly"],
            "severity": "HIGH",
            "title": "Secure transfer is disabled",
            "reason": (
                "The storage account permits non-HTTPS traffic."
            ),
            "recommendation": (
                "Enable secure transfer for the storage account."
            )
        })

    # Rule 3: Minimum TLS
    if actual_state["minimumTlsVersion"] != "TLS1_2":
        findings.append({
            "setting": "minimumTlsVersion",
            "expected": intended_state["minimumTlsVersion"],
            "actual": actual_state["minimumTlsVersion"],
            "severity": "MEDIUM",
            "title": "Weak TLS version configured",
            "reason": (
                "The storage account is configured with "
                "a TLS version below the intended baseline."
            ),
            "recommendation": (
                "Use TLS 1.2 or the currently approved minimum."
            )
        })

            # Rule 4: Public network access
    if actual_state["publicNetworkAccess"] == "Enabled":
        findings.append({
            "setting": "publicNetworkAccess",
            "expected": "Disabled",
            "actual": actual_state["publicNetworkAccess"],
            "severity": "MEDIUM",
            "title": "Public network access is enabled",
            "reason": (
                "The storage account permits network access "
                "through its public endpoint. Access may still "
                "be restricted by network rules and authentication."
            ),
            "recommendation": (
                "Disable public network access if private "
                "connectivity is sufficient for the workload."
            )
        })

    return findings