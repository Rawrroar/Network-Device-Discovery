"""Resolve discovery credentials from Nautobot Secrets Groups.

Credential selection mirrors the Nautobot Device Discovery app:

- **SSH**: secrets groups assigned to the profile are ordered by ascending
  weight; a stored last-known-working group (from a previous successful
  collection on that IP) is attempted first, then all others in weight
  order until authentication succeeds.
- **SNMP**: only the lowest-weight group that defines SNMP secrets is used —
  no fallback attempts.
- **SNMPv3** security levels are derived from the secrets present in the
  group: username only (noAuthNoPriv), username + password (authNoPriv),
  username + password + key (authPriv).

All values are retrieved lazily via ``SecretsGroup.get_secret_value()`` so
external secret providers (environment variables, hashicorp vault, ...) are
honored at query time rather than stored on the profile.
"""

from nautobot.extras.choices import (
    SecretsGroupAccessTypeChoices,
    SecretsGroupSecretTypeChoices,
)

from .models import DiscoveryProfile

_SNMP_V3_ACCESS_TYPE = SecretsGroupAccessTypeChoices.TYPE_SNMP
_SSH_ACCESS_TYPE = SecretsGroupAccessTypeChoices.TYPE_SSH


def ordered_secrets_groups(profile):
    """Return the profile's secrets groups ordered by ascending weight.

    Ties are broken by group name so ordering is deterministic.
    """
    if profile is None:
        return []
    return [
        assignment.secrets_group
        for assignment in profile.secrets_group_assignments.select_related("secrets_group").order_by(
            "weight", "secrets_group__name"
        )
    ]


def _get_secret(group, access_type, secret_type):
    """Fetch one secret value, returning None on any retrieval error."""
    try:
        value = group.get_secret_value(access_type=access_type, secret_type=secret_type)
    except Exception:
        return None
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _snmp_v3_secrets_for_group(group):
    """Extract SNMPv3 USM credentials from a single secrets group.

    Returns (version, config_dict) or (None, None) when the group does not
    define an SNMP username. ``version`` is ``"2c"`` when a Token (community)
    secret is present without a Username, otherwise ``"3"``.
    """
    username = _get_secret(group, _SNMP_V3_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_USERNAME)
    if username:
        password = _get_secret(group, _SNMP_V3_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_PASSWORD)
        key = _get_secret(group, _SNMP_V3_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_KEY)
        return "3", {
            "snmp_version": "3",
            "snmpv3_username": username,
            "snmpv3_auth_key": password or "",
            "snmpv3_priv_key": key or "",
        }
    community = _get_secret(group, _SNMP_V3_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_TOKEN)
    if community:
        return "2c", {"snmp_version": "2c", "snmp_community": community}
    return None, None


def snmp_secrets_config(profile, config=None):
    """Resolve SNMP credentials for a profile.

    Only the lowest-weight group that defines SNMP secrets is consulted;
    groups are skipped silently when a secret cannot be retrieved.

    Returns:
        dict of SNMP config overrides (possibly empty), or None when no
        group provides SNMP credentials. On None, callers should fall back
        to job/plugin-supplied credentials.
    """
    for group in ordered_secrets_groups(profile):
        version, overrides = _snmp_v3_secrets_for_group(group)
        if version is None:
            continue
        merged = dict(config or {})
        merged.update(overrides)
        if version == "3":
            merged["snmpv3_auth_protocol"] = merged.get("snmpv3_auth_protocol") or "SHA"
            merged["snmpv3_priv_protocol"] = merged.get("snmpv3_priv_protocol") or "AES"
        return merged
    return None


def ssh_credential_candidates(profile, config=None, preferred_group=None):
    """Return ordered SSH credential candidates for a profile.

    Args:
        profile: DiscoveryProfile (may be None).
        config: optional base config dict merged into each candidate.
        preferred_group: SecretsGroup whose credentials should be attempted
            first (the last known working group for this device), regardless
            of weight ordering.

    Returns:
        list of dicts with keys ``username``, ``password`` and (optionally)
        ``secrets_group``; empty when no profile or no usable secrets.
    """
    groups = ordered_secrets_groups(profile)
    if preferred_group is not None and preferred_group in groups:
        groups.remove(preferred_group)
        groups.insert(0, preferred_group)

    candidates = []
    for group in groups:
        username = _get_secret(group, _SSH_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_USERNAME)
        if not username:
            continue
        password = _get_secret(group, _SSH_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_PASSWORD)
        candidate = dict(config or {})
        candidate.update({"username": username, "password": password or "", "secrets_group": group})
        candidates.append(candidate)
    return candidates


def ssh_credential_from_config(config):
    """Build a single SSH credential candidate from job/plugin config values."""
    username = (config.get("ssh_username") or "").strip()
    if not username:
        return None
    candidate = dict(config)
    candidate.update({"username": username, "password": config.get("ssh_password") or "", "secrets_group": None})
    return candidate


def ssh_credential_candidates_for_group(group, config=None):
    """Build a single SSH credential candidate from one specific secrets group.

    Used by the Fast Path to collect data with the stored last-known-working
    credentials only — no iteration, no fallback.

    Returns:
        candidate dict, or None when the group has no usable SSH username.
    """
    if group is None:
        return None
    username = _get_secret(group, _SSH_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_USERNAME)
    if not username:
        return None
    password = _get_secret(group, _SSH_ACCESS_TYPE, SecretsGroupSecretTypeChoices.TYPE_PASSWORD)
    candidate = dict(config or {})
    candidate.update({"username": username, "password": password or "", "secrets_group": group})
    return candidate


def ssh_connect_with_credentials(ip_str, candidates, connect_func, **connect_kwargs):
    """Try each SSH credential candidate in order until one succeeds.

    Args:
        ip_str: target IP address.
        candidates: list from :func:`ssh_credential_candidates` (or a single
            dict built by :func:`ssh_credential_from_config`).
        connect_func: the SSH collection callable (e.g.
            ``ssh_connect_and_discover``); called as
            ``connect_func(ip_str, username, password, **connect_kwargs)``.
        **connect_kwargs: forwarded to ``connect_func`` unchanged.

    Returns:
        ``(info, candidate)`` from the first successful candidate, or
        ``(None, None)`` when every candidate fails or the list is empty.
    """
    if candidates is None:
        candidates = []
    elif isinstance(candidates, dict):
        candidates = [candidates]
    for candidate in candidates:
        info = connect_func(
            ip_str,
            candidate["username"],
            candidate["password"],
            **connect_kwargs,
        )
        if info:
            return info, candidate
    return None, None


def record_ssh_success(discovered_device, candidate):
    """Persist the last known working SSH secrets group on a device record."""
    if discovered_device is None or candidate is None:
        return
    group = candidate.get("secrets_group")
    if group is not None and getattr(discovered_device, "ssh_secrets_group_id", None) != group.pk:
        discovered_device.ssh_secrets_group = group
        discovered_device.save(update_fields=["ssh_secrets_group"])


def profile_secrets_groups_or_none(profile):
    """Return ordered groups for the profile, or None when it has none."""
    groups = ordered_secrets_groups(profile)
    return groups or None


__all__ = [
    "DiscoveryProfile",
    "ordered_secrets_groups",
    "profile_secrets_groups_or_none",
    "record_ssh_success",
    "snmp_secrets_config",
    "ssh_credential_candidates",
    "ssh_credential_candidates_for_group",
    "ssh_credential_from_config",
    "ssh_connect_with_credentials",
]
