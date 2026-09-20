# Detection Rule Generation (Brief #4, Phase 2).
#
# Deterministic, ground-truth-only Sigma rule generator. Rules are NOT
# speculative: each rule is produced ONLY where the local MITRE ATT&CK
# knowledge base records that the actor uses the technique (a stix relation
# exists), and the technique has an analyst-owned detection template below —
# the same "explicit mapping table owned by the analysts" pattern as
# `app/tactics.py` and `app/actor_profile.py`. Techniques without a template
# are reported honestly as "unmapped" and produce nothing.

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any

# -----------------------------------------------------------------------------
# Analyst-owned technique -> Sigma template.
#
# `logsource`, `detection` and `falsepositives` are standard Sigma idioms for
# the corresponding ATT&CK technique (community field names). They are
# heuristics owned by the analysts, not data — every generated rule carries an
# explicit "review before deployment" note and the generator only ever attaches
# a rule to a technique that the KB records the actor using.
# -----------------------------------------------------------------------------

TECHNIQUE_TO_SIGMA: dict[str, dict[str, Any]] = {
    "T1105": {
        # Ingress Tool Transfer
        "logsource": {"product": "windows", "category": "net_connection"},
        "detection": {
            "selection": {"EventID": 3, "Initiated": "true"},
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate downloads by users or administrators",
            "Software update and file-sync traffic",
        ],
        "level": "low",
    },
    "T1204.002": {
        # Malicious File
        "logsource": {"product": "windows", "category": "file_event"},
        "detection": {
            "selection": {
                "EventID": 11,
                "TargetFilename|contains": ["\\Downloads\\", "\\Desktop\\"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Users legitimately saving files to Downloads or Desktop",
        ],
        "level": "low",
    },
    "T1059.001": {
        # PowerShell
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
                "CommandLine|contains": [
                    "-enc",
                    "-EncodedCommand",
                    "-e ",
                    "-Command",
                ],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Administrative or automation scripts legitimately using PowerShell",
        ],
        "level": "medium",
    },
    "T1059.003": {
        # Windows Command Shell
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\cmd.exe"],
                "CommandLine|contains": ["/c ", "-Command"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate batch scripts and installer helpers invoking cmd.exe",
        ],
        "level": "medium",
    },
    "T1588.002": {
        # Tool acquisition
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\curl.exe", "\\wget.exe", "\\certutil.exe"],
                "CommandLine|contains": ["http://", "https://"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Developers and admins legitimately downloading tooling",
        ],
        "level": "low",
    },
    "T1566.001": {
        # Spearphishing Attachment
        "logsource": {"product": "office365", "category": "email"},
        "detection": {
            "selection": {
                "AttachmentName|endswith": [
                    ".docm", ".xlsm", ".lnk", ".iso", ".scr", ".dll",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate email messages with office documents or archive files",
        ],
        "level": "medium",
    },
    "T1036.005": {
        # Masquerading: Match Legitimate Name or Location
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "\\svchost.exe", "\\explorer.exe", "\\rundll32.exe",
                ],
                "CommandLine|contains": ["-enc ", ".ps1"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate uses of well-known system binaries",
        ],
        "level": "low",
    },
    "T1082": {
        # System Information Discovery
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "systeminfo", "hostname", "ver ",
                    "wmic", "Get-WmiObject",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate troubleshooting commands",
        ],
        "level": "low",
    },
    "T1071.001": {
        # Web Protocols (C2)
        "logsource": {"product": "windows", "category": "net_connection"},
        "detection": {
            "selection": {
                "EventID": 3,
                "Initiated": "true",
                "DestinationPort": [80, 443],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "All regular outbound web browsing matches this — tune to a known-bad host list or enrich with DNS/proxy data before use",
        ],
        "level": "low",
    },
    "T1547.001": {
        # Registry Run Keys / Startup Folder
        "logsource": {"product": "windows", "category": "registry_event"},
        "detection": {
            "selection": {
                "EventID": 12,
                "TargetObject|contains": ["\\CurrentVersion\\RunOnce"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate programs registering autostart entries",
        ],
        "level": "medium",
    },
    "T1053.005": {
        # Scheduled Task
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\schtasks.exe"],
                "CommandLine|contains": ["/create", "/run"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Administrative automation legitimately creating scheduled tasks",
        ],
        "level": "medium",
    },
    "T1083": {
        # File and Directory Discovery
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": ["\\cmd.exe", "\\powershell.exe"],
                "CommandLine|contains": ["/s", "/b", "Get-ChildItem"],
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate directory listing during administration",
        ],
        "level": "low",
    },
    "T1055": {
        # Process Injection
        "logsource": {"product": "windows", "category": "process_access"},
        "detection": {
            "selection": {
                "EventID": 10,
                "GrantedAccess": "0x1410",
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Antivirus/EDR components legitimately inspecting other processes",
        ],
        "level": "medium",
    },
    "T1003": {
        # Credential Dumping (OS Credential Dumping)
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "sekurlsa", "mimikatz", "lsass", "procdump", "comsvcs.dll",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Authentication tooling and legitimate diagnostics touching lsass",
        ],
        "level": "high",
    },
    "T1078": {
        # Valid Accounts (logon events)
        "logsource": {"product": "windows", "service": "security"},
        "detection": {
            "selection": {"EventID": [4624, 4648], "LogonType": [3, 10]},
            "condition": "selection",
        },
        "falsepositives": [
            "Regular successful logons — baseline and tune before use",
        ],
        "level": "low",
    },
    "T1219": {
        # Remote Access Software
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": [
                    "\\anydesk.exe", "\\teamviewer.exe",
                    "\\sunloginclient.exe", "\\ammyy-admin.exe",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate remote-support software installed by IT",
        ],
        "level": "low",
    },
    "T1027": {
        # Obfuscated Files or Information (decode/encode abuse)
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "CommandLine|contains": [
                    "certutil -decode", "FromBase64String",
                    "ConvertTo-SecureString",
                ]
            },
            "condition": "selection",
        },
        "falsepositives": [
            "Legitimate use of encoding utilities by applications",
        ],
        "level": "high",
    },
}

# Map a sub-technique without its own template to its parent template, e.g.
# T1059.001 -> T1059.001 (exact), T1105.001 -> T1105. The fallback only ever
# points to a template that actually exists as a top-level key (never the
# reverse: a bare parent whose only coverage is a sub-template), so nothing is
# ever generated from a mismatched detector.
def _template_key(x_mitre_id: str) -> str | None:
    if x_mitre_id in TECHNIQUE_TO_SIGMA:
        return x_mitre_id
    parent = x_mitre_id.rsplit(".", 1)[0]
    if parent != x_mitre_id and parent in TECHNIQUE_TO_SIGMA:
        return parent
    return None


# -----------------------------------------------------------------------------
# Minimal, dependency-free YAML writer (Sigma is YAML). Only the shapes this
# generator emits are supported: flat maps, scalar lists, nested maps.
# -----------------------------------------------------------------------------

_INT_RE = re.compile(r"^-?\d+$")
_FLOAT_RE = re.compile(r"^-?\d+\.\d+$")
_SPECIAL = ("- ", "? ", ": ", "{", "}", "[", "]", ",", "&", "*", "#", "|",
            ">", "!", "%", "@", "`", "'", '"', "~")
_AMBIGUOUS = {"true", "false", "null", "yes", "no", "on", "off"}


def _scalar(value: Any) -> str:
    """Render a scalar as a safe YAML token (quote conservatively)."""
    if value is None:
        return '""'
    s = str(value)
    if not s:
        return '""'
    if _INT_RE.match(s) or _FLOAT_RE.match(s):
        return s
    if s.startswith(_SPECIAL) or ": " in s or " #" in s or s in _AMBIGUOUS:
        return "'" + s.replace("'", "''") + "'"
    return s


def _yaml_list(items: list[Any], indent: str) -> list[str]:
    lines = []
    for item in items:
        if isinstance(item, dict):
            for i, (k, v) in enumerate(item.items()):
                lines.append(f"{indent}- {k}: {_scalar(v)}" if i == 0 else f"{indent}  {k}: {_scalar(v)}")
        else:
            lines.append(f"{indent}- {_scalar(item)}")
    return lines


def _yaml_map(mapping: dict[str, Any], indent: str) -> list[str]:
    """Emit a mapping whose values may be scalars, lists or nested maps."""
    lines: list[str] = []
    for key in mapping:
        value = mapping[key]
        if isinstance(value, list):
            lines.append(f"{indent}{key}:")
            lines.extend(_yaml_list(value, indent + "    "))
        elif isinstance(value, dict):
            lines.append(f"{indent}{key}:")
            lines.extend(_yaml_map(value, indent + "    "))
        elif isinstance(value, str) and "\n" in value:
            # Multi-line text -> literal block scalar (valid for any content,
            # including apostrophes and colons).
            lines.append(f"{indent}{key}: |")
            for ln in value.rstrip("\n").split("\n"):
                lines.append(f"{indent}    {ln}")
        else:
            lines.append(f"{indent}{key}: {_scalar(value)}")
    return lines


# -----------------------------------------------------------------------------
# Rule construction (all content is grounded in real KB fields).
# -----------------------------------------------------------------------------

def _tactic_tag(tactic: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (tactic or "unknown").lower()).strip("-")
    return f"attack.{slug}"


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")[:60] or "actor"


def build_rule(
    actor_name: str,
    actor_stix_id: str,
    actor_url: str,
    motivation: str,
    attribution: str,
    malware_names: list[str],
    technique: dict[str, Any],
) -> dict[str, Any]:
    """Build one Sigma rule (as a dict + its YAML text) for an (actor,
    technique) pair recorded in the KB. Distilled from -- never fabricates --
    the MITRE ATT&CK data we hold."""
    x_mitre_id = technique["x_mitre_id"]
    technique_name = technique["name"]
    tactic = technique["tactic"]
    technique_url = technique["url"] or ""
    technique_desc = (technique.get("description") or "").strip()

    tid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"argus-cti::{actor_stix_id}::{x_mitre_id}"))

    origin = attribution or "not stated"
    lines_desc = [
        f"{technique_name} ({x_mitre_id}) activity that is consistent with the threat actor '{actor_name}'.",
        "",
        f"Generator basis: the ATT&CK knowledge base records {actor_name} using this "
        f"technique (motivation: {motivation}, attribution: {origin}).",
    ]
    if technique_desc:
        snippet = technique_desc[:400]
        if len(technique_desc) > 400:
            snippet += " …"
        lines_desc += ["", "Technique summary:", snippet]
    if malware_names:
        lines_desc += [
            "",
            "KB-attributed malware/tools of this actor: "
            + ", ".join(malware_names[:6]),
        ]
    description = "\n".join(lines_desc)

    template_key = _template_key(x_mitre_id)
    template = TECHNIQUE_TO_SIGMA[template_key]

    references = []
    if technique_url:
        references.append(technique_url)
    if actor_url:
        references.append(actor_url)

    tags = [f"attack.{x_mitre_id.lower()}", _tactic_tag(tactic),
            f"actor.{_slugify(actor_name)}"]

    date = datetime.now(timezone.utc).strftime("%Y/%m/%d")

    mapping: dict[str, Any] = {
        "title": f"Potential {actor_name} activity - {technique_name}",
        "id": tid,
        "status": "experimental",
        "description": description,
        "author": "Argus CTI - automated ATT&CK KB generator",
        "date": date,
        "references": references,
        "tags": tags,
        "logsource": template["logsource"],
        "detection": template["detection"],
        "falsepositives": template["falsepositives"],
        "level": template["level"],
    }

    yaml_lines = [
        "# Auto-generated by Argus CTI (Brief #4, Phase 2) from the local MITRE",
        "# ATT&CK knowledge base. REVIEW this rule before deployment.",
    ]
    yaml_lines += _yaml_map(mapping, "")
    sigma = "\n".join(yaml_lines) + "\n"

    return {
        "rule_id": tid,
        "title": f"Potential {actor_name} activity - {technique_name}",
        "x_mitre_id": x_mitre_id,
        "technique_name": technique_name,
        "tactic": tactic,
        "level": template["level"],
        "template": template_key,
        "sigma": sigma,
        "references": references,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def generate(
    actor: dict[str, Any],
    techniques: list[dict[str, Any]],
    malware_names: list[str],
) -> dict[str, Any]:
    """Deterministically generate detection rules for one actor.

    Techniques recorded in the KB *and* covered by an analyst template are
    generated; everything else is reported as `unmapped` (honest, empty by
    design). Never fabricates a rule for a technique the KB does not attach to
    the actor.
    """
    rules = []
    unmapped = []
    for technique in techniques:
        key = technique.get("x_mitre_id") or ""
        covered = _template_key(key) is not None
        if not covered:
            unmapped.append({
                "x_mitre_id": key,
                "name": technique.get("name", ""),
                "tactic": technique.get("tactic", ""),
            })
            continue
        rules.append(build_rule(
            actor["name"],
            actor["stix_id"],
            actor["url"],
            actor["motivation"],
            actor["attribution"],
            malware_names,
            technique,
        ))

    rules.sort(key=lambda r: (r["tactic"], r["x_mitre_id"], r["technique_name"]))

    note = (
        "Rules are generated deterministically from the local MITRE ATT&CK "
        "knowledge base: a rule exists only for techniques the KB records this "
        "actor using AND that have an analyst-owned Sigma template. They are "
        "starting points for detection engineering — review before deployment."
    )
    return {
        "actor": {"name": actor["name"], "stix_id": actor["stix_id"]},
        "generated": len(rules),
        "unmapped_count": len(unmapped),
        "unmapped": unmapped,
        "rules": rules,
        "note": note,
    }