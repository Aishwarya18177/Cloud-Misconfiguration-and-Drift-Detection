import json
import sys

from pathlib import Path

from collector.nsg_collector import (
    collect_nsg_state,
    NSG_NAME
)

from collector.nsg_security_rules import (
    check_nsg_security_rules
)

from database.database import (
    create_database,
    create_scan_table,
    start_scan,
    finish_scan,
    complete_scan
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

BASELINE_PATH = (
    PROJECT_ROOT / "collector" / "nsg_intended_state.json"
)


# ============================================================
# Normalize rules
# ============================================================

def rules_by_name(rules):
    if not isinstance(rules, list):
        raise ValueError(
            "custom_rules must be a JSON list."
        )

    result = {}

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError(
                "Each custom rule must be an object."
            )

        name = rule.get("name")

        if not isinstance(name, str) or not name.strip():
            raise ValueError(
                "Every custom rule needs a name."
            )

        if name in result:
            raise ValueError(
                f"Duplicate rule name: {name}"
            )

        normalized = {}

        for field, value in rule.items():
            if isinstance(value, list):
                if not all(
                    isinstance(item, str)
                    for item in value
                ):
                    raise ValueError(
                        f"{name}: {field} must contain strings."
                    )

                normalized[field] = sorted(set(value))

            else:
                normalized[field] = value

        result[name] = normalized

    return result


# ============================================================
# Compare rules
# ============================================================

def compare_rules(intended_rules, actual_rules):
    expected = rules_by_name(intended_rules)
    actual = rules_by_name(actual_rules)

    changes = []

    for name in sorted(set(expected) | set(actual)):
        if name not in expected:
            changes.append({
                "type": "ADDED",
                "rule_name": name,
                "expected": None,
                "actual": actual[name]
            })

        elif name not in actual:
            changes.append({
                "type": "REMOVED",
                "rule_name": name,
                "expected": expected[name],
                "actual": None
            })

        elif expected[name] != actual[name]:
            fields = sorted(
                set(expected[name]) | set(actual[name])
            )

            changed_fields = [
                field
                for field in fields
                if (
                    field not in expected[name]
                    or field not in actual[name]
                    or expected[name][field] != actual[name][field]
                )
            ]

            changes.append({
                "type": "MODIFIED",
                "rule_name": name,
                "changed_fields": changed_fields,
                "expected": expected[name],
                "actual": actual[name]
            })

    return changes


def classify_result(changes, findings):
    if changes and findings:
        return "DRIFT + SECURITY MISCONFIGURATION"

    if findings:
        return "SECURITY MISCONFIGURATION"

    if changes:
        return "DRIFT DETECTED"

    return "COMPLIANT"


# ============================================================
# Run and save the NSG assessment
# ============================================================

def main():
    try:
        create_database()
        create_scan_table()

        scan_id = start_scan(NSG_NAME)

    except Exception as error:
        print(f"\nUnable to initialize NSG scan: {error}")
        return 1

    print(f"\nSCAN ID: {scan_id}")
    print(f"RESOURCE: {NSG_NAME}")

    try:
        with BASELINE_PATH.open(
            "r",
            encoding="utf-8"
        ) as file:
            intended = json.load(file)

        if not isinstance(intended, dict):
            raise ValueError(
                "The NSG baseline must be a JSON object."
            )

        expected_name = intended.get("resource_name")

        if not isinstance(expected_name, str) or not expected_name:
            raise ValueError(
                "The NSG baseline needs a resource_name."
            )

        if "custom_rules" not in intended:
            raise ValueError(
                "The NSG baseline needs a custom_rules list."
            )

        rules_by_name(intended["custom_rules"])

        state = collect_nsg_state()

        if (
            expected_name.casefold()
            != state["resource_name"].casefold()
        ):
            raise ValueError(
                "Baseline and collected NSG names do not match."
            )

        if state["resource_name"] != NSG_NAME:
            raise ValueError(
                "Collected NSG name does not match the scan resource."
            )

        changes = compare_rules(
            intended["custom_rules"],
            state["custom_rules"]
        )

        findings = check_nsg_security_rules(state)

        result = classify_result(
            changes,
            findings
        )

        complete_scan(
            scan_id=scan_id,
            resource_name=state["resource_name"],
            findings=findings,
            drift_count=len(changes),
            result=result
        )

    except Exception as error:
        try:
            finish_scan(
                scan_id=scan_id,
                status="FAILED",
                error_message=str(error)
            )

        except Exception as history_error:
            print(
                "Could not save the scan failure: "
                f"{history_error}"
            )

        print("\n========================================")
        print(f"SCAN ID: {scan_id}")
        print("SCAN STATUS: FAILED")
        print(f"ERROR: {error}")
        print("========================================")

        return 1

    print("\n========== NSG DRIFT CHECK ==========")

    if not changes:
        print(
            "Custom rules match the approved baseline."
        )

    else:
        for change in changes:
            print(
                f"\n[{change['type']}] "
                f"{change['rule_name']}"
            )

            if change["type"] == "MODIFIED":
                print(
                    "Changed fields: "
                    + ", ".join(change["changed_fields"])
                )

            print("Expected:")
            print(json.dumps(change["expected"], indent=2))

            print("Actual:")
            print(json.dumps(change["actual"], indent=2))

    print("\n========== SECURITY FINDINGS ==========")

    if not findings:
        print(
            "No risky custom inbound rules "
            "matched the configured checks."
        )

    else:
        for finding in findings:
            print(f"\n[{finding['severity']}]")
            print(f"Check: {finding['check_id']}")
            print(f"Rule: {finding['rule_name']}")
            print(f"Finding: {finding['title']}")
            print(f"Reason: {finding['reason']}")

            print(
                "Recommendation: "
                + finding["recommendation"]
            )

    attached = bool(
        state["subnet_ids"]
        or state["network_interface_ids"]
    )

    print("\n========================================")
    print(f"SCAN ID: {scan_id}")
    print(f"RESOURCE: {state['resource_name']}")
    print("SCAN STATUS: SUCCESS")
    print(f"ATTACHED TO A WORKLOAD: {attached}")
    print(f"RULES WITH DRIFT: {len(changes)}")
    print(f"SECURITY FINDINGS: {len(findings)}")
    print(f"RESULT: {result}")
    print("NSG findings and scan history saved.")
    print("========================================")

    print(
        "\nScope: custom-rule baseline and configured checks, "
        "not effective network reachability."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())