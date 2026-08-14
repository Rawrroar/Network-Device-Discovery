"""Small shared helpers for the Device Auto-Discovery plugin."""


def strip_domain_suffixes(hostname, suffixes):
    """Strip configured domain suffixes from a discovered hostname.

    Matching follows the Nautobot Device Discovery app semantics:
    case-insensitive, longest matching suffix wins, a dot boundary is
    required before the suffix, the original case of the remaining
    hostname is preserved, and a single trailing root dot is tolerated.

    Returns:
        str hostname with the longest matching suffix removed, unchanged
        when nothing matches or no suffixes are configured.
    """
    if not hostname or not suffixes:
        return hostname

    host = hostname
    trailing_dot = False
    if host.endswith(".") and not host.endswith(".."):
        host = host.rstrip(".")
        trailing_dot = True

    host_lower = host.lower()
    best = ""
    for suffix in suffixes:
        entry = (suffix or "").strip().strip(".")
        if not entry:
            continue
        entry_lower = entry.lower()
        if host_lower.endswith("." + entry_lower) and len(entry_lower) > len(best):
            best = entry_lower

    if best:
        cut = len(host_lower) - len(best) - 1  # index of the leading dot
        return host[:cut]

    return hostname if not trailing_dot else host
