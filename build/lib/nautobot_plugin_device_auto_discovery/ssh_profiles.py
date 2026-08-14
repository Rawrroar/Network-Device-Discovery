"""Vendor SSH command and parsing profiles.

Each profile maps a detected vendor to the commands used to identify a
device over SSH plus the regex patterns used to extract hostname, model,
serial number, and OS version from the captured output.

Profiles are keyed by the canonical vendor name returned by
``detect_vendor_from_descr`` / ``VENDOR_KEYWORDS`` in ``jobs.py``.
A ``None`` vendor falls back to a generic command list and generic
regexes (see ``ssh_connect_and_discover``).
"""

# Profile structure:
# {
#     "vendor_keywords": tuple of regexes matched against command output/banner,
#     "requires_enable": bool - escalate a ">" shell prompt to "#" before commands,
#     "pre_commands": list of commands run first to disable paging (errors ignored),
#     "commands": list of identification commands to run,
#     "parsers": {
#         "hostname": [regex...],
#         "model":    [regex...],
#         "serial":   [regex...],
#         "os_version": [regex...],
#     },
# }
# Each parser regex is searched against the concatenated command output.
# The first matching group is used, or the whole match if no group is present.

SSH_PROFILES = {
    "Cisco": {
        "vendor_keywords": ("cisco",),
        "requires_enable": True,
        "pre_commands": ["terminal length 0"],
        "commands": ["show version", "show inventory"],
        "parsers": {
            "hostname": [
                r"(?:hostname|host)\s+(\S+)",
                r"^([A-Za-z0-9_.-]+)[>#]\s*$",
            ],
            "model": [
                r"PID:\s*(\S+)",
                r"Model\s*(?:number|name|description)?\s*[:\s]+(\S+)",
                r"Cisco\s+([A-Za-z0-9][A-Za-z0-9\-]+)(?:\s|$)",
            ],
            "serial": [
                r"Processor board ID\s+(\S+)",
                r"Serial\s*(?:number|id|#)?\s*[:\s]+(\S+)",
                r"SN:\s*(\S+)",
            ],
            "os_version": [
                r"Cisco IOS-XE Software[^\n]*?Version\s+([0-9a-zA-Z.()]+)",
                r"Cisco IOS Software[^\n]*?Version\s+([0-9a-zA-Z.()]+)",
                r"Cisco IOS-XR[^\n]*?Version\s+([0-9a-zA-Z.()]+)",
                r"system image file is[^\n]*?bootflash:([\S]+)",
            ],
        },
    },
    "Juniper Networks": {
        "vendor_keywords": ("juniper",),
        "requires_enable": False,
        "pre_commands": ["set cli screen-length 0", "set cli screen-width 0"],
        "commands": ["show version", "show chassis hardware"],
        "parsers": {
            "hostname": [
                r"Hostname:\s*(\S+)",
                r"(?:hostname|host)\s*[:\s]+(\S+)",
            ],
            "model": [
                r"Model:\s*(\S+)",
                r"Chassis:\s*(\S+)",
            ],
            "serial": [
                r"^Chassis\s+(\S+)\s+(\S+)\s*$",
                r"Serial\s*number\s*[:]\s*(\S+)",
                r"Serial\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"Junos:\s*([0-9A-Za-z.]+(?:-?R\d+)?)",
                r"JUNOS\s+([0-9A-Za-z.]+)",
            ],
        },
    },
    "Arista Networks": {
        "vendor_keywords": ("arista",),
        "requires_enable": False,
        "pre_commands": ["terminal length 0"],
        "commands": ["show version"],
        "parsers": {
            "hostname": [
                r"(?:hostname|host)\s+(\S+)",
            ],
            "model": [
                r"Model\s*number\s*[:\s]+(\S+)",
                r"Hardware\s*[:\s]+(\S+)",
            ],
            "serial": [
                r"System\s*serial\s*number\s*[:\s]+(\S+)",
                r"Serial\s*number\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"version\s*[:\s]+(\S+)",
                r"ArubaOS\s+([0-9A-Za-z.]+)",
            ],
        },
    },
    "HPE": {
        "vendor_keywords": ("hp|hpe|procurve|comware",),
        "requires_enable": True,
        "pre_commands": ["screen-length disable"],
        "commands": ["display version", "display device manuinfo"],
        "parsers": {
            "hostname": [
                r"^\s*(\S+)\s*\[.*?\]\s*$",
                r"(?:hostname|host)\s+(\S+)",
            ],
            "model": [
                r"HPE\s+([A-Za-z0-9\-]+) Software",
                r"HP\s+([A-Za-z0-9\-]+) Software",
                r"(?:Aruba|ProCurve|Comware)\s+([A-Za-z0-9\-]+)",
                r"DEVICE_NAME\s*[:\s]+(\S+)",
                r"DEVICE_MODEL\s*[:\s]+(\S+)",
            ],
            "serial": [
                r"DEVICE_SERIAL_NUMBER\s*[:\s]+(\S+)",
                r"Serial\s*number\s*[:\s]+(\S+)",
                r"SN\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"Comware Software[^\n]*?Version\s+([0-9A-Za-z.]+)",
                r"Version\s+([0-9A-Za-z.]+)[^\n]*",
                r"Software\s+Version\s*[:\s]+([0-9A-Za-z.]+)",
            ],
        },
    },
    "Nokia": {
        "vendor_keywords": ("nokia|alcatel",),
        "requires_enable": False,
        "pre_commands": ["environment no more"],
        "commands": ["show system version", "show system information", "show chassis"],
        "parsers": {
            "hostname": [
                r"System Name\s*[:\s]+(\S+)",
                r"(?:hostname|host)\s*[:\s]+(\S+)",
            ],
            "model": [
                r"System Type\s*[:\s]+(\S+)",
                r"Model\s*[:\s]+(\S+)",
            ],
            "serial": [
                r"Chassis\s*[:\s]+(\S+)",
                r"Serial\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"System Version\s*[:\s]+([0-9A-Za-z.]+(?:-R\d+)?)",
                r"Release\s*[:\s]+([0-9A-Za-z.]+)",
                r"Version\s*[:\s]+([0-9A-Za-z.]+)",
            ],
        },
    },
    "Fortinet": {
        "vendor_keywords": ("fortinet|forti",),
        "requires_enable": False,
        "pre_commands": ["config system console", "set output standard", "end"],
        "commands": ["get system status"],
        "parsers": {
            "hostname": [
                r"Hostname\s*[:\s]+(\S+)",
                r"Hostname:\s*(\S+)",
            ],
            "model": [
                r"Model\s*name\s*[:\s]+(\S+)",
                r"Model\s*[:\s]+(\S+)",
            ],
            "serial": [
                r"Serial-Number\s*[:\s]+(\S+)",
                r"Serial\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"Version\s*[:\s]+(Forti[A-Za-z0-9.]+\s+v\d+\.\d+\S*)",
                r"Version\s*[:\s]+([0-9a-zA-Z.]+(?:[MF]\d+)?)",
            ],
        },
    },
    "Palo Alto Networks": {
        "vendor_keywords": ("palo alto|panos|paloalto",),
        "requires_enable": False,
        "pre_commands": ["set cli pager off", "set cli pagination off"],
        "commands": ["show system info"],
        "parsers": {
            "hostname": [
                r"hostname\s*[:\s]+(\S+)",
                r"hostname:\s*(\S+)",
            ],
            "model": [
                r"model\s*[:\s]+(\S+)",
                r"model:\s*(\S+)",
            ],
            "serial": [
                r"serial\s*[:\s]+(\S+)",
                r"serial:\s*(\S+)",
            ],
            "os_version": [
                r"sw-version\s*[:\s]+([0-9a-zA-Z.]+)",
                r"sw-version:\s*([0-9a-zA-Z.]+)",
            ],
        },
    },
    "Ubiquiti": {
        "vendor_keywords": ("ubiquiti|edge|unifi",),
        "requires_enable": False,
        "pre_commands": ["terminal length 0"],
        "commands": ["show version"],
        "parsers": {
            "hostname": [
                r"(?:hostname|host)\s+(\S+)",
            ],
            "model": [
                r"Hardware\s*[:\s]+(\S+)",
                r"HW\s*(?:model|version)?\s*[:\s]+(\S+)",
                r"Model\s*[:\s]+(\S+)",
            ],
            "serial": [
                r"Serial\s*[:\s]+(\S+)",
                r"SN\s*[:\s]+(\S+)",
            ],
            "os_version": [
                r"Version\s*[:\s]+v?([0-9][0-9A-Za-z.]*)",
                r"Firmware\s*[:\s]+v?([0-9][0-9A-Za-z.]*)",
            ],
        },
    },
}

# Commands attempted for devices whose vendor could not be determined.
GENERIC_INFO_COMMANDS = [
    "show version",
    "display version",
    "show system information",
    "display current-version",
]
