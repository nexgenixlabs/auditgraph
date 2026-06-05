"""SSRF guard for outbound webhook URLs.

AG-102: every outbound POST that follows an admin-supplied URL has to
pass through assert_webhook_safe() first. Blocks:

  - Non-http(s) schemes (file://, gopher://, javascript:, etc.)
  - http:// in production (only https:// allowed)
  - Hostnames that resolve to private / link-local / loopback addresses:
      10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16   (RFC1918)
      127.0.0.0/8                                  (loopback)
      169.254.0.0/16                               (Azure IMDS lives here!)
      ::1, fc00::/7, fe80::/10                     (IPv6 equivalents)
  - DNS rebinding: re-resolves the hostname before allowing — guards
    against an attacker who registers attacker.com → 1.1.1.1, then
    flips to 169.254.169.254 between validation and request.

Production callers should:
    from app.services.webhook_guard import assert_webhook_safe, WebhookGuardError
    try:
        assert_webhook_safe(webhook['url'])
    except WebhookGuardError as e:
        return jsonify({'error': str(e), 'code': 'ssrf_blocked'}), 400
    requests.post(webhook['url'], ...)

The guard runs at BOTH registration time (reject the URL at /api/webhooks
POST) and at dispatch time (defence-in-depth against DNS rebinding +
stored URLs that were registered before the guard existed).
"""
from __future__ import annotations
import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WebhookGuardError(ValueError):
    """Raised when a webhook URL fails the SSRF safety check."""


# Private / reserved IP ranges that must never receive an outbound webhook.
_BLOCKED_NETS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),       # Azure IMDS
    ipaddress.ip_network('0.0.0.0/8'),            # "this network"
    ipaddress.ip_network('100.64.0.0/10'),        # CG-NAT
    ipaddress.ip_network('::1/128'),              # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),             # IPv6 ULA
    ipaddress.ip_network('fe80::/10'),            # IPv6 link-local
    ipaddress.ip_network('::ffff:127.0.0.0/104'), # IPv4-mapped loopback
    ipaddress.ip_network('::ffff:169.254.0.0/112'),
]


def _ip_is_private_or_reserved(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # unparseable → reject
    return any(addr in net for net in _BLOCKED_NETS)


def assert_webhook_safe(url: str, allow_http_in_dev: bool = True) -> None:
    """Raise WebhookGuardError if `url` would be unsafe to POST to.

    The function resolves the hostname and checks all returned IPs (some
    DNS records return multiple A records — all must be public).

    Args:
        url: webhook URL to validate
        allow_http_in_dev: when APP_ENV=local/dev, permit http:// for
            localhost-style smoke testing. Production always rejects.
    """
    if not url or not isinstance(url, str):
        raise WebhookGuardError("Webhook URL is required.")
    parsed = urlparse(url.strip())

    # Scheme
    if parsed.scheme not in ('http', 'https'):
        raise WebhookGuardError(
            f"Webhook scheme must be http or https; got {parsed.scheme!r}."
        )
    _is_prod = os.getenv('APP_ENV', 'local') not in ('local', 'dev')
    if parsed.scheme == 'http' and (_is_prod or not allow_http_in_dev):
        raise WebhookGuardError(
            "Webhook URL must use https:// in production."
        )

    if not parsed.hostname:
        raise WebhookGuardError("Webhook URL is missing a hostname.")
    host = parsed.hostname.strip()

    # Reject IP literals that are private — covers the trivial case before DNS.
    try:
        addr = ipaddress.ip_address(host)
        if _ip_is_private_or_reserved(str(addr)):
            raise WebhookGuardError(
                f"Webhook host {host!r} is a private/reserved IP. Refused to send."
            )
    except ValueError:
        pass  # not an IP literal — resolve via DNS

    # Resolve the hostname and reject if any returned A record is private.
    # This is the DNS-rebinding-resistant check: we resolve right before
    # the assertion, callers do the actual POST immediately after.
    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == 'https' else 80))
    except socket.gaierror as e:
        raise WebhookGuardError(f"Webhook host {host!r} does not resolve: {e}")
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _ip_is_private_or_reserved(ip):
            raise WebhookGuardError(
                f"Webhook host {host!r} resolves to private/reserved IP {ip}. "
                f"Refused to send (SSRF guard)."
            )
    # All resolved IPs are public — safe to proceed.
