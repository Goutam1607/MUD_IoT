"""
acl_enforcer.py — ACL Rule Simulation
Parses and enforces ACL rules extracted from a MUD file.
"""

import ipaddress


class ACLEnforcer:
    def __init__(self):
        # Stores rules per device: {device_id: [rule, ...]}
        self.device_rules = {}

    def apply_mud_policy(self, device_id: str, mud_data: dict):
        """Parse MUD file ACLs and store rules for the device."""
        rules = []
        try:
            acls = mud_data.get("ietf-access-control-list:acls", {}).get("acl", [])
            for acl in acls:
                acl_name = acl.get("name", "unnamed")
                direction = "from" if "from" in acl_name else "to"
                aces = acl.get("aces", {}).get("ace", [])
                for ace in aces:
                    rule = self._parse_ace(ace, direction)
                    if rule:
                        rules.append(rule)
            self.device_rules[device_id] = rules
            print(f"[ACL ENFORCER] Applied {len(rules)} ACL rules for '{device_id}'")
        except Exception as e:
            print(f"[ACL ENFORCER] Error parsing ACL: {e}")

    def _parse_ace(self, ace: dict, direction: str) -> dict | None:
        """Convert an ACE entry into a simplified rule dict."""
        try:
            matches = ace.get("matches", {})
            actions = ace.get("actions", {})
            ipv4 = matches.get("ipv4", {})
            tcp = matches.get("tcp", {})
            udp = matches.get("udp", {})

            # Determine port
            port_info = tcp.get("dst-port") or tcp.get("src-port") or \
                        udp.get("dst-port") or udp.get("src-port") or {}
            port = port_info.get("port") if isinstance(port_info, dict) else None

            # Determine protocol
            protocol = "tcp" if tcp else ("udp" if udp else "any")

            return {
                "name": ace.get("name", "unnamed"),
                "direction": direction,
                "dst_address": ipv4.get("dst-address") or ipv4.get("src-address", "0.0.0.0/0"),
                "port": port,
                "protocol": protocol,
                "action": actions.get("forwarding", "drop")
            }
        except Exception:
            return None

    def check_traffic(self, device_id: str, dst_ip: str, dst_port: int, protocol: str) -> bool:
        """
        Check whether a packet from the device to dst_ip:dst_port is allowed.
        Returns True = ACCEPT, False = DROP.
        """
        rules = self.device_rules.get(device_id, [])
        if not rules:
            print(f"[ACL ENFORCER] No rules found for '{device_id}' — defaulting to DROP")
            return False

        for rule in rules:
            if rule["direction"] != "from":
                continue
            if rule["protocol"] != "any" and rule["protocol"] != protocol:
                continue
            if rule["port"] is not None and rule["port"] != dst_port:
                continue
            try:
                network = ipaddress.ip_network(rule["dst_address"], strict=False)
                if ipaddress.ip_address(dst_ip) in network:
                    return rule["action"] == "accept"
            except ValueError:
                continue

        # Default deny
        return False

    def show_rules(self, device_id: str):
        """Pretty-print all ACL rules for a device."""
        rules = self.device_rules.get(device_id, [])
        print(f"\n[ACL ENFORCER] Rules for '{device_id}':")
        for r in rules:
            print(f"  [{r['action'].upper()}] {r['direction']} | {r['protocol'].upper()} "
                  f"→ {r['dst_address']}:{r['port'] or 'any'} ({r['name']})")
