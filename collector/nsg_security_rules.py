import ipaddress
import json
import sys


# ============================================================
# Identify unrestricted sources
# ============================================================

def is_unrestricted_source(source):
    source = str(source).strip()

    if source.lower() in {"*", "internet"}:
        return True

    try:
        network = ipaddress.ip_network(
            source,
            strict=False
        )

        # Covers both 0.0.0.0/0 and ::/0.
        return network.prefixlen == 0

    except ValueError:
        # Other service tags are outside these initial checks.
        return False


# ============================================================
# Read individual ports and port ranges
# ============================================================

def parse_port_ranges(values):
    ranges = []

    for value in values:
        text = str(value).strip()

        if text == "*":
            ranges.append((0, 65535))

        elif "-" in text:
            start, end = text.split("-", 1)

            start = int(start)
            end = int(end)

            if not 0 <= start <= end <= 65535:
                raise ValueError(
                    f"Invalid destination port range: {text}"
                )

            ranges.append((start, end))

        else:
            port = int(text)

            if not 0 <= port <= 65535:
                raise ValueError(
                    f"Invalid destination port: {text}"
                )

            ranges.append((port, port))

    return ranges


def includes_port(ranges, port):
    return any(
        start <= port <= end
        for start, end in ranges
    )


def includes_all_ports(ranges):
    """Check whether ranges cover every port from 1 to 65535."""

    next_port = 1

    for start, end in sorted(ranges):
        if end < next_port:
            continue

        if start > next_port:
            return False

        next_port = max(next_port, end + 1)

        if next_port > 65535:
            return True

    return False


# ============================================================
# Build a finding
# ============================================================

def make_finding(
    state,
    rule,
    check_id,
    severity,
    title,
    reason,
    recommendation
):
    return {
        "resource_id": state["resource_id"],
        "resource_name": state["resource_name"],
        "check_id": check_id,
        "rule_name": rule["name"],

        # A separate identity for each rule and security check.
        "setting": f"rules/{rule['name']}/{check_id}",

        "severity": severity,
        "title": title,
        "expected": (
            "Restrict inbound access to approved sources "
            "and required destination ports."
        ),
        "actual": rule,
        "reason": reason,
        "recommendation": recommendation
    }


# ============================================================
# NSG security checks
# ============================================================

def check_nsg_security_rules(state):
    findings = []

    for rule in state["custom_rules"]:
        direction = str(rule["direction"]).lower()
        access = str(rule["access"]).lower()
        protocol = str(rule["protocol"]).lower()

        # These checks apply only to inbound allow rules.
        if direction != "inbound" or access != "allow":
            continue

        unrestricted = any(
            is_unrestricted_source(source)
            for source in rule["source_addresses"]
        )

        if not unrestricted:
            continue

        # Port-based checks apply to TCP, UDP or all protocols.
        if protocol not in {"tcp", "udp", "*"}:
            continue

        if not rule["destination_ports"]:
            raise ValueError(
                f"Rule {rule['name']} has no destination ports."
            )

        port_ranges = parse_port_ranges(
            rule["destination_ports"]
        )

        # Rule 1: All destination ports.
        if includes_all_ports(port_ranges):
            findings.append(
                make_finding(
                    state=state,
                    rule=rule,
                    check_id="NSG-ALL-PORTS",
                    severity="CRITICAL",
                    title=(
                        "Inbound allow rule covers all "
                        "destination ports from an unrestricted source"
                    ),
                    reason=(
                        "This rule permits every destination port "
                        "for its configured protocol and destinations "
                        "from an unrestricted source."
                    ),
                    recommendation=(
                        "Limit the source to approved networks and "
                        "allow only the destination ports required "
                        "by the workload."
                    )
                )
            )

            # Avoid separate SSH/RDP findings for the same
            # all-port rule.
            continue

        # Rule 2: SSH.
        if (
            protocol in {"tcp", "*"}
            and includes_port(port_ranges, 22)
        ):
            findings.append(
                make_finding(
                    state=state,
                    rule=rule,
                    check_id="NSG-SSH",
                    severity="HIGH",
                    title=(
                        "SSH allow rule uses an unrestricted source"
                    ),
                    reason=(
                        "The rule includes inbound TCP port 22 "
                        "from an unrestricted source."
                    ),
                    recommendation=(
                        "Restrict SSH to approved administrator "
                        "source addresses or use an approved "
                        "private management access method."
                    )
                )
            )

        # Rule 3: RDP can use TCP and UDP.
        if includes_port(port_ranges, 3389):
            findings.append(
                make_finding(
                    state=state,
                    rule=rule,
                    check_id="NSG-RDP",
                    severity="HIGH",
                    title=(
                        "RDP allow rule uses an unrestricted source"
                    ),
                    reason=(
                        "The rule includes inbound port 3389 "
                        "from an unrestricted source."
                    ),
                    recommendation=(
                        "Restrict RDP to approved administrator "
                        "source addresses or use an approved "
                        "private management access method."
                    )
                )
            )

    return findings


# ============================================================
# Run against the real Azure NSG
# ============================================================

def main():
    from collector.nsg_collector import collect_nsg_state

    try:
        state = collect_nsg_state()
        findings = check_nsg_security_rules(state)

    except Exception as error:
        print(f"\nNSG SECURITY CHECK FAILED: {error}")
        return 1

    attached = bool(
        state["subnet_ids"]
        or state["network_interface_ids"]
    )

    print("\n========== NSG SECURITY CHECK ==========")
    print(f"Resource: {state['resource_name']}")
    print(f"Attached to a workload: {attached}")
    print(f"Custom rules inspected: {len(state['custom_rules'])}")
    print(f"Security findings: {len(findings)}")

    if not findings:
        print(
            "\nNo risky custom inbound rules "
            "matched these security checks."
        )

    else:
        for finding in findings:
            rule = finding["actual"]

            print(f"\n[{finding['severity']}]")
            print(f"Check: {finding['check_id']}")
            print(f"Rule: {finding['rule_name']}")
            print(f"Priority: {rule['priority']}")
            print(f"Finding: {finding['title']}")
            print(f"Reason: {finding['reason']}")

            print(
                "Recommendation: "
                + finding["recommendation"]
            )

            print("Rule configuration:")
            print(json.dumps(rule, indent=2))

    print(
        "\nScope: configured custom rules, "
        "not effective network reachability."
    )

    print(
        "No Azure settings changed. "
        "NSG findings have not been written to the database."
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())