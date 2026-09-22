from __future__ import annotations

import asyncio
import logging
import httpx
from datetime import datetime, timezone
import clickhouse_connect

from app.config import settings
from app.db import insert_rows
from app.actor_profile import profile_from_description
from app.threat_classify import classify_malware

logger = logging.getLogger(__name__)

ATTACK_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

# enterprise-attack kill_chain_phases[].phase_name -> display label (MITRE 14 tactics).
TACTIC_LABELS: dict[str, str] = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}

class AttackImporter:
    """Fetches and ingests the MITRE ATT&CK STIX 2.1 dataset into ClickHouse."""
    
    def __init__(self, db_client: clickhouse_connect.driver.asyncclient.AsyncClient):
        self.db = db_client
        self.db_name = settings.clickhouse_database
        
    async def sync(self) -> dict[str, int]:
        """Downloads STIX dataset, parses objects, and inserts them."""
        logger.info("Starting MITRE ATT&CK sync from %s", ATTACK_STIX_URL)
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(ATTACK_STIX_URL)
            resp.raise_for_status()
            bundle = resp.json()
            
        objects = bundle.get("objects", [])
        logger.info("Fetched %d STIX objects", len(objects))
        
        actors = []
        malware_tools = []
        patterns = []
        relationships = []
        
        now = datetime.now(timezone.utc)
        
        def _get_mitre_url_and_id(ext_refs):
            url = ""
            ext_id = ""
            for ref in ext_refs:
                if ref.get("source_name") == "mitre-attack":
                    url = ref.get("url", "")
                    ext_id = ref.get("external_id", "")
                    break
            return url, ext_id
            
        def _parse_time(ts_str):
            if not ts_str:
                return datetime(1970, 1, 1, tzinfo=timezone.utc)
            # handle formats like "2019-09-01T04:00:00.000Z"
            try:
                # remove Z for fromisoformat in older pythons if needed, 
                # but python 3.11+ handles Z
                return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except ValueError:
                return datetime(1970, 1, 1, tzinfo=timezone.utc)

        for obj in objects:
            obj_type = obj.get("type")
            stix_id = obj.get("id")
            if not stix_id:
                continue
                
            name = obj.get("name", "")
            desc = obj.get("description", "")
            aliases = obj.get("aliases", [])
            if obj_type == "malware" and "x_mitre_aliases" in obj:
                 aliases.extend(obj.get("x_mitre_aliases", []))
                 
            url, ext_id = _get_mitre_url_and_id(obj.get("external_references", []))
            
            if obj_type == "intrusion-set":
                first_seen = _parse_time(obj.get("first_seen"))
                last_seen = _parse_time(obj.get("last_seen"))
                profile = profile_from_description(desc)
                actors.append((
                    stix_id, name, desc, aliases, first_seen, last_seen, url,
                    profile["motivation"], profile["attribution"],
                    profile["target_sectors"], profile["target_countries"],
                    now,
                ))
                
            elif obj_type in ("malware", "tool"):
                malware_tools.append((
                    stix_id, name, obj_type, desc, aliases, url,
                    classify_malware(name, desc), now,
                ))
                
            elif obj_type == "attack-pattern":
                tactic = "unknown"
                for kcp in obj.get("kill_chain_phases", []) or []:
                    phase = (kcp.get("phase_name") or "").strip()
                    if phase:
                        tactic = TACTIC_LABELS.get(phase, phase.replace("-", " ").title())
                        break
                patterns.append((stix_id, ext_id, tactic, name, desc, url, now))
                
            elif obj_type == "relationship":
                src = obj.get("source_ref", "")
                tgt = obj.get("target_ref", "")
                rel = obj.get("relationship_type", "")
                relationships.append((stix_id, src, tgt, rel, now))
                
        # Insert actors
        if actors:
            await insert_rows(
                self.db,
                f"{self.db_name}.threat_actors",
                actors,
                ["stix_id", "name", "description", "aliases", "first_seen", "last_seen",
                 "url", "motivation", "attribution", "target_sectors", "target_countries", "ts"]
            )
            
        # Insert malware/tools
        if malware_tools:
            await insert_rows(
                self.db,
                f"{self.db_name}.malware_tools",
                malware_tools,
                ["stix_id", "name", "type", "description", "aliases", "url", "category", "ts"]
            )
            
        # Insert attack patterns
        if patterns:
            await insert_rows(
                self.db,
                f"{self.db_name}.attack_patterns",
                patterns,
                ["stix_id", "x_mitre_id", "tactic", "name", "description", "url", "ts"]
            )
            
        # Insert relationships
        if relationships:
            await insert_rows(
                self.db,
                f"{self.db_name}.stix_relationships",
                relationships,
                ["stix_id", "source_ref", "target_ref", "relationship_type", "ts"]
            )
            
        logger.info("Inserted %d actors, %d malware/tools, %d TTPs, %d relationships", 
                    len(actors), len(malware_tools), len(patterns), len(relationships))
        
        return {
            "actors": len(actors),
            "malware_tools": len(malware_tools),
            "attack_patterns": len(patterns),
            "relationships": len(relationships)
        }
