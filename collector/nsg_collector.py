import json
import sys

from datetime import datetime, timezone

from azure.identity import AzureCliCredential
from azure.mgmt.network import NetworkManagementClient


# ============================================================
# Azure configuration
# ============================================================

SUBSCRIPTION_ID = "3295c2de-964f-43f0-8429-6ef55498e26d"
RESOURCE_GROUP = "driftstore"
NSG_NAME = "driftlab-nsg"


# ============================================================
# Normalize SDK values
# ============================================================

def text_value(value):
    if value is None:
        return None

    return str(getattr(value, "value", value))


def combined_values(rule, single_field, multiple_field):
    """Handle rules containing either one value or several."""

    values = list(
        getattr(rule, multiple_field, None) or []
    )

    single_value = getattr(
        rule,
        single_field,
        None
    )

    if single_value is not None:
        values.append(single_value)

    return sorted({
        text_value(value)
        for value in values
        if value is not None
    })


def normalize_rule(rule):
    """Convert an Azure rule into a plain Python dictionary."""

    return {
        "name": rule.name,
        "priority": rule.priority,
        "direction": text_value(rule.direction),
        "access": text_value(rule.access),
        "protocol": text_value(rule.protocol),

        "source_addresses": combined_values(
            rule,
            "source_address_prefix",
            "source_address_prefixes"
        ),

        "source_ports": combined_values(
            rule,
            "source_port_range",
            "source_port_ranges"
        ),

        "destination_addresses": combined_values(
            rule,
            "destination_address_prefix",
            "destination_address_prefixes"
        ),

        "destination_ports": combined_values(
            rule,
            "destination_port_range",
            "destination_port_ranges"
        ),

        "source_application_security_groups": sorted(
            group.id
            for group in (
                rule.source_application_security_groups or []
            )
            if group.id
        ),

        "destination_application_security_groups": sorted(
            group.id
            for group in (
                rule.destination_application_security_groups or []
            )
            if group.id
        )
    }


# ============================================================
# Collect NSG configuration
# ============================================================

def collect_nsg_state():
    credential = AzureCliCredential()

    try:
        client = NetworkManagementClient(
            credential,
            SUBSCRIPTION_ID
        )

        try:
            nsg = client.network_security_groups.get(
                RESOURCE_GROUP,
                NSG_NAME
            )

            custom_rules = [
                normalize_rule(rule)
                for rule in (nsg.security_rules or [])
            ]

            default_rules = [
                normalize_rule(rule)
                for rule in (nsg.default_security_rules or [])
            ]

            subnet_ids = [
                subnet.id
                for subnet in (nsg.subnets or [])
            ]

            interface_ids = [
                interface.id
                for interface in (nsg.network_interfaces or [])
            ]

            state = {
                "resource_id": nsg.id,
                "resource_name": nsg.name,
                "resource_group": RESOURCE_GROUP,
                "location": nsg.location,

                "collected_at": (
                    datetime.now(timezone.utc).isoformat()
                ),

                "subnet_ids": subnet_ids,
                "network_interface_ids": interface_ids,

                "custom_rules": sorted(
                    custom_rules,
                    key=lambda rule: (
                        rule["direction"] or "",
                        rule["priority"]
                        if rule["priority"] is not None
                        else 99999,
                        rule["name"] or ""
                    )
                ),

                "default_rules": sorted(
                    default_rules,
                    key=lambda rule: (
                        rule["direction"] or "",
                        rule["priority"]
                        if rule["priority"] is not None
                        else 99999,
                        rule["name"] or ""
                    )
                )
            }

        finally:
            client.close()

    finally:
        credential.close()

    return state


# ============================================================
# Command-line output
# ============================================================

def main():
    try:
        state = collect_nsg_state()

    except Exception as error:
        print(f"\nNSG COLLECTION FAILED: {error}")
        return 1

    print("\n========== NSG COLLECTION ==========")
    print(f"Name: {state['resource_name']}")
    print(f"Location: {state['location']}")

    print(
        "Attached subnets:",
        len(state["subnet_ids"])
    )

    print(
        "Attached network interfaces:",
        len(state["network_interface_ids"])
    )

    print(
        "Custom rules:",
        len(state["custom_rules"])
    )

    print(
        "Default rules:",
        len(state["default_rules"])
    )

    attached = (
        state["subnet_ids"]
        or state["network_interface_ids"]
    )

    if attached:
        print("\nLAB STATUS: ATTACHED")
        print(
            "Review the associations before adding test rules."
        )
    else:
        print("\nLAB STATUS: UNATTACHED")

    print("\n========== CUSTOM RULES ==========")

    if state["custom_rules"]:
        print(
            json.dumps(
                state["custom_rules"],
                indent=2
            )
        )
    else:
        print("No custom rules configured.")

    print("\n========== DEFAULT RULES ==========")

    for rule in state["default_rules"]:
        print(
            f"{rule['priority']} | "
            f"{rule['direction']} | "
            f"{rule['access']} | "
            f"{rule['name']}"
        )

    print("\nCollection completed. No Azure settings changed.")
    print("Security assessment has not been run yet.")

    return 0


if __name__ == "__main__":
    sys.exit(main())