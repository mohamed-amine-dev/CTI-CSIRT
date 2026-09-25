# =============================================================================
# CTI Platform - shared private/reserved IP classification
# -----------------------------------------------------------------------------
# Single source of truth for "is this IP a *public* attacker host?". Every
# surface that treats an IP as a malicious IOC (extraction, corpus lookup,
# PCAP cross-reference, geolocation) uses this one definition so internal
# infrastructure addresses (RFC1918, CGNAT, loopback, link-local, multicast,
# TEST-NET, ...) can never be flagged or consumed as threat intel.
# =============================================================================

from __future__ import annotations

import ipaddress


def is_ip_address(value: str) -> bool:
    """True when `value` parses as a concrete IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def is_non_public_ip(value: str) -> bool:
    """True when `value` is an IP that is NOT a routable public unicast address.

    Excluded ranges (IANA-reserved / non-routable on the public internet):
      * RFC1918     10/8, 172.16/12, 192.168/16
      * CGNAT       100.64/10            (is_global=False but is_private=False)
      * TEST-NET    192.0.2/24, 198.51.100/24, 203.0.113/24
      * other       0/8, 127/8, 169.254/16, 224/4 multicast, 255.255.255.255
      * IPv6        ::, ::1, fe80::/10, fc00::/7 (ULA), ff00::/8 multicast
    Unparseable strings return False so callers can keep their own error type
    (this helper only classifies *real* addresses).
    """
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return False
    if (
        addr.is_multicast
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return True
    if addr.is_private:
        return True
    if addr.version == 4:
        # Closes the CGNAT (100.64/10) and broadcast gaps in `is_private`.
        return not addr.is_global
    if addr.is_site_local:
        return True
    return False