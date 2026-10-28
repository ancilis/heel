"""
Heel hosted — worker egress guard (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Default-deny allowlist a worker consults before ANY outbound connection during a run. The only
hosts ever allowed are the run's verified target(s); private/loopback/link-local ranges and
non-HTTP(S) ports are refused even for allowlisted names, so a target that resolves inward
(DNS rebinding) is still blocked at connect time via `allows_ip`.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple = ()
    allowed_ports: tuple = (80, 443)

    def allows_host(self, hostname: str, port: int = 443) -> bool:
        h = (hostname or "").strip().lower().rstrip(".")
        if not h or port not in self.allowed_ports:
            return False
        try:  # literal IPs are never allowlisted by name
            ipaddress.ip_address(h)
            return False
        except ValueError:
            pass
        return any(h == a or h.endswith("." + a)
                   for a in (x.strip().lower().rstrip(".") for x in self.allowed_hosts))

    def allows_ip(self, ip: str) -> bool:
        """Post-resolution check: refuse private, loopback, link-local, multicast, reserved."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return not (addr.is_private or addr.is_loopback or addr.is_link_local
                    or addr.is_multicast or addr.is_reserved or addr.is_unspecified)

    def check(self, hostname: str, resolved_ip: str, port: int = 443) -> None:
        """Single call for workers; raises PermissionError with the reason."""
        if not self.allows_host(hostname, port):
            raise PermissionError(f"egress denied: {hostname}:{port} not in run allowlist")
        if not self.allows_ip(resolved_ip):
            raise PermissionError(f"egress denied: {hostname} resolves to non-public {resolved_ip}")
