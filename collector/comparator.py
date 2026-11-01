import json
import sys

from pathlib import Path

from collector.security_rules import check_security_rules

from database.database import (
    create_database,
    create_scan_table,
    save_finding,
    resolve_findings,
    start_scan,
    finish_scan
)


# ============================================================
# Configuration
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASELINE_PATH = (
    PROJECT_ROOT / "collector" / "intended_state.json"
)

SUBSCRIPTION_ID = "3295c2de-964f-43f0-8429-6ef55498e26d"
RESOURCE_GROUP = "driftstore"
STORAGE_ACCOUNT = "clouddriftlab2026"


# ============================================================
# Read current Azure configuration
# ============================================================

def collect_actual_state():
    from azure.identity import AzureCliCredential
    from azure.mgmt.storage import StorageManagementClient

    credential = AzureCliCredential()

    try:
        client = StorageManagementClient(
            credential,
            SUBSCRIPTION_ID
        )

        try:
            account = client.storage_accounts.get_properties(
                RESOURCE_GROUP,
                STORAGE_ACCOUNT
            )

            raw = account.as_dict()
            properties = raw.get("properties", raw)

            fields = {
                "allowBlobPublicAccess":
                    "allow_blob_public_access",

                "publicNetworkAccess":
                    "public_network_access",

                "minimumTlsVersion":
                    "minimum_tls_version",

                "allowSharedKeyAccess":
                    "allow_shared_key_access",

                "supportsHttpsTrafficOnly":
                    "enable_https_traffic_only"
            }

            actual_state = {}

            for setting, attribute in fields.items():
                value = properties.get(
                    setting,
                    properties.get(
                        attribute,
                        getattr(account, attribute, None)
                    )
                )

                actual_state[setting] = getattr(
                    value,
                    "value",
                    value
                )

        finally:
            client.close()

    finally:
        credential.close()

    missing = [
        setting
        for setting, value in actual_state.items()
        if value is None
    ]

    if missing:
        raise ValueError(
            "Azure returned unknown configuration values for: "
            + ", ".join(missing)
        )

    return actual_state


# ============================================================
# Classify assessment result
# ============================================================

def classify_result(drift_count, findings):
    if drift_count and findings:
        return "DRIFT + SECURITY MISCONFIGURATION"

    if findings:
        return "SECURITY MISCONFIGURATION"

    if drift_count:
        return "DRIFT DETECTED"

    return "COMPLIANT"


# ============================================================
# Run a complete scan
# ============================================================

def main():
    # Prepare the database before starting the scan.
    try:
        create_database()
        create_scan_table()

        scan_id = start_scan(STORAGE_ACCOUNT)

    except Exception as error:
        print(f"\nUnable to initialize scan history: {error}")
        print("The scan did not start.")
        return 1

    print(f"\nSCAN ID: {scan_id}")
    print(f"RESOURCE: {STORAGE_ACCOUNT}")

    try:
        # ----------------------------------------------------
        # Load intended configuration
        # ----------------------------------------------------

        with BASELINE_PATH.open(
            "r",
            encoding="utf-8"
        ) as file:
            intended_state = json.load(file)

        if (
            not isinstance(intended_state, dict)
            or not intended_state
        ):
            raise ValueError(
                "intended_state.json must contain "
                "a nonempty JSON object."
            )

        # ----------------------------------------------------
        # Collect actual configuration
        # ----------------------------------------------------

        actual_state = collect_actual_state()

        unsupported = (
            set(intended_state) - set(actual_state)
        )

        if unsupported:
            raise ValueError(
                "The baseline contains unsupported settings: "
                + ", ".join(sorted(unsupported))
            )

        # ----------------------------------------------------
        # Compare intended and actual values
        # ----------------------------------------------------

        print("\n========== DRIFT CHECK ==========")

        drift_count = 0

        for setting, expected in intended_state.items():
            actual = actual_state[setting]

            if expected == actual:
                print(f"[MATCH] {setting}")

            else:
                drift_count += 1

                print(f"[DRIFT] {setting}")
                print(f"  Expected: {expected}")
                print(f"  Actual:   {actual}")

        # ----------------------------------------------------
        # Run security rules
        # ----------------------------------------------------

        print("\n========== SECURITY FINDINGS ==========")

        findings = check_security_rules(
            actual_state,
            intended_state
        )

        if not findings:
            print("No security misconfigurations detected.")

        else:
            for finding in findings:
                print(f"\n[{finding['severity']}]")
                print(f"Setting: {finding['setting']}")
                print(f"Finding: {finding['title']}")
                print(f"Expected: {finding['expected']}")
                print(f"Actual: {finding['actual']}")
                print(f"Reason: {finding['reason']}")

                print(
                    "Recommendation: "
                    + finding["recommendation"]
                )

        # ----------------------------------------------------
        # Update finding history
        # Only reached after collection and assessment succeed.
        # ----------------------------------------------------

        for finding in findings:
            save_finding(finding)

        resolve_findings(findings)

        # ----------------------------------------------------
        # Record successful scan
        # ----------------------------------------------------

        result = classify_result(
            drift_count,
            findings
        )

        finish_scan(
            scan_id=scan_id,
            status="SUCCESS",
            result=result,
            drift_count=drift_count,
            finding_count=len(findings)
        )

    except Exception as error:
        # Failed scans have unknown counts, not zero findings.
        try:
            finish_scan(
                scan_id=scan_id,
                status="FAILED",
                error_message=str(error)
            )

        except Exception as history_error:
            print(
                "\nCould not save the scan failure: "
                f"{history_error}"
            )

        print("\n========================================")
        print(f"SCAN ID: {scan_id}")
        print("SCAN STATUS: FAILED")
        print(f"ERROR: {error}")
        print("No successful assessment was recorded.")
        print("========================================")

        return 1

    # --------------------------------------------------------
    # Display summary
    # --------------------------------------------------------

    print("\n========================================")
    print(f"SCAN ID: {scan_id}")
    print("SCAN STATUS: SUCCESS")
    print(f"CONFIGURATION DRIFTS: {drift_count}")
    print(f"SECURITY FINDINGS: {len(findings)}")
    print(f"RESULT: {result}")
    print("Scan history saved.")
    print("========================================")

    return 0


if __name__ == "__main__":
    sys.exit(main())