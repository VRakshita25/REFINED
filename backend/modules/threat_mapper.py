"""
modules/threat_mapper.py — MalDNA Step 8
Threat Actor Attribution Engine

Maps malware family → known threat actors, TTPs, campaigns, infrastructure,
geopolitical context, and recommended containment actions.

Data sources:
  - MITRE ATT&CK Groups
  - Malpedia threat actor database
  - Public threat intelligence reports
  - Manual curation from vendor research

No external API needed — self-contained knowledge base.
"""

# ─────────────────────────────────────────────────────────────────
# THREAT ACTOR KNOWLEDGE BASE
# Each entry: family name (lowercase) → actor profile
# ─────────────────────────────────────────────────────────────────

THREAT_ACTORS = {

    "mozi": {
        "actor_name":       "Mozi Operators",
        "actor_id":         "TA-MOZI-001",
        "also_known_as":    ["Mozi Gang", "DHT Botnet Crew"],
        "origin":           "China",
        "motivation":       ["Financial", "DDoS-for-hire", "Cryptomining"],
        "active_since":     "2019",
        "active_until":     "2023 (C2 kill switch activated by Chinese authorities)",
        "status":           "DORMANT — kill switch deployed Sep 2023, legacy samples still circulate",
        "threat_level":     "HIGH",

        "description": (
            "Mozi is a P2P botnet that exploits weak Telnet credentials and "
            "known router vulnerabilities to infect IoT devices. It uses a "
            "BitTorrent-like DHT protocol for C2 communications, making it "
            "resilient to takedown. At peak, Mozi comprised ~1.5 million infected "
            "devices globally. In September 2023, an unknown party (believed to be "
            "Chinese authorities) sent a kill switch command that disabled the botnet."
        ),

        "targeted_sectors":  ["Telecom", "ISP Infrastructure", "Smart Home", "Industrial IoT"],
        "targeted_regions":  ["China", "India", "Russia", "Brazil", "Global"],

        "capabilities": [
            "DDoS attacks (UDP/TCP/HTTP flood)",
            "Telnet credential brute-forcing",
            "Router/IoT vulnerability exploitation",
            "Payload download and execution",
            "Network traffic proxying",
            "Persistence via crontab and init scripts",
            "Self-propagation via DHT P2P network",
        ],

        "exploited_cves": [
            {"cve": "CVE-2018-10561", "description": "GPON ONT authentication bypass",       "severity": "CRITICAL"},
            {"cve": "CVE-2018-10562", "description": "GPON ONT command injection",            "severity": "CRITICAL"},
            {"cve": "CVE-2017-17215", "description": "Huawei HG532 remote code execution",   "severity": "HIGH"},
            {"cve": "CVE-2019-16920", "description": "D-Link remote code execution",          "severity": "CRITICAL"},
            {"cve": "CVE-2014-8361",  "description": "Realtek SDK miniigd UPnP RCE",          "severity": "HIGH"},
            {"cve": "CVE-2017-18368", "description": "ZyXEL router command injection",        "severity": "CRITICAL"},
        ],

        "mitre_techniques": [
            {"id": "T1190",    "name": "Exploit Public-Facing Application",   "tactic": "Initial Access"},
            {"id": "T1078.001","name": "Valid Accounts: Default Credentials", "tactic": "Initial Access"},
            {"id": "T1059.004","name": "Unix Shell",                          "tactic": "Execution"},
            {"id": "T1027",    "name": "Obfuscated Files (UPX packing)",      "tactic": "Defense Evasion"},
            {"id": "T1053.003","name": "Cron persistence",                    "tactic": "Persistence"},
            {"id": "T1498",    "name": "Network Denial of Service",           "tactic": "Impact"},
            {"id": "T1071.001","name": "Web Protocols (HTTP C2)",             "tactic": "C2"},
            {"id": "T1105",    "name": "Ingress Tool Transfer",               "tactic": "C2"},
            {"id": "T1083",    "name": "File and Directory Discovery",        "tactic": "Discovery"},
        ],

        "ioc_patterns": [
            "Outbound DHT traffic on non-standard ports",
            "Connections to Baidu (connectivity check: +://baidu)",
            "HTTP GET/POST to /Mozi.m* paths",
            "Crontab entries pointing to /tmp executables",
            "iptables rules blocking ports 23, 2323, 7547",
            "Processes named after random alphanumeric strings in /tmp",
        ],

        "infrastructure": {
            "c2_protocol":  "BitTorrent DHT (P2P, no central C2)",
            "c2_ports":     ["6881", "6882", "random high ports"],
            "update_url":   "http://<node>:<port>/Mozi.m<arch>",
            "persistence":  ["/etc/crontabs/root", "/etc/init.d/", "rc.local"],
            "drop_paths":   ["/tmp/", "/var/tmp/", "/dev/shm/"],
        },

        "related_families": ["Mirai", "Gafgyt", "LightAidra"],
        "references": [
            "https://blog.netlab.360.com/mozi-another-botnet-using-dht/",
            "https://www.welivesecurity.com/2023/09/27/mozi-story-ends/",
            "https://unit42.paloaltonetworks.com/mozi-botnet/",
        ],

        "analyst_notes": (
            "Despite the kill switch, Mozi binaries continue to circulate on "
            "MalwareBazaar as IoT devices remain unpatched. Detection of Mozi "
            "indicates an unpatched IoT device with default credentials. "
            "Priority: patch CVE-2018-10561/10562 and change default router passwords."
        ),
    },

    "mirai": {
        "actor_name":    "Paras Jha / Josiah White / Dalton Norman (original) + hundreds of forks",
        "actor_id":      "TA-MIRAI-001",
        "also_known_as": ["Anna-senpai", "Mirai Botnet Authors"],
        "origin":        "United States (original authors), Global (fork operators)",
        "motivation":    ["DDoS-for-hire", "Financial", "Notoriety"],
        "active_since":  "2016",
        "active_until":  "Ongoing (open-source forks still active)",
        "status":        "ACTIVE — source code leaked 2016, thousands of variants exist",
        "threat_level":  "CRITICAL",

        "description": (
            "Mirai infected ~600,000 IoT devices in 2016 and conducted record-breaking "
            "DDoS attacks including the Dyn DNS attack that took down major internet "
            "services. Source code was leaked by the author in 2016, spawning hundreds "
            "of variants (Satori, Okiru, Masuta, etc.). Original authors pleaded guilty "
            "in 2017. Variants remain extremely active."
        ),

        "targeted_sectors":  ["DNS Infrastructure", "Gaming", "Hosting", "Media", "IoT Devices"],
        "targeted_regions":  ["Global"],

        "capabilities": [
            "Massive DDoS (UDP/TCP/GRE/HTTP flood)",
            "Telnet/SSH brute-forcing with 60+ default credential pairs",
            "60+ IoT device exploit modules (variants)",
            "Self-propagation via scanner",
            "Kill competing malware processes",
            "Persistence via watchdog process",
        ],

        "exploited_cves": [
            {"cve": "CVE-2016-10401", "description": "ZyXEL default credential",            "severity": "HIGH"},
            {"cve": "CVE-2017-17215", "description": "Huawei HG532 RCE",                   "severity": "HIGH"},
            {"cve": "CVE-2014-8361",  "description": "Realtek miniigd UPnP RCE",            "severity": "HIGH"},
        ],

        "mitre_techniques": [
            {"id": "T1078.001","name": "Default Credentials",              "tactic": "Initial Access"},
            {"id": "T1059.004","name": "Unix Shell",                       "tactic": "Execution"},
            {"id": "T1498",    "name": "Network Denial of Service",        "tactic": "Impact"},
            {"id": "T1046",    "name": "Network Service Scanning",         "tactic": "Discovery"},
            {"id": "T1053.003","name": "Cron",                             "tactic": "Persistence"},
            {"id": "T1071.001","name": "Web Protocols",                    "tactic": "C2"},
        ],

        "ioc_patterns": [
            "Mass Telnet scanning on port 23/2323",
            "Binary named after random string in /tmp or /dev",
            "Connections to hardcoded C2 IPs on port 23/48101",
            "Process kills competing malware (busybox ps, kill)",
            "Watchdog process to restart if killed",
        ],

        "infrastructure": {
            "c2_protocol":  "Custom TCP binary protocol",
            "c2_ports":     ["23", "48101", "103", "7547"],
            "persistence":  ["/dev/shm/", "/tmp/", "watchdog process"],
            "drop_paths":   ["/tmp/", "/dev/"],
        },

        "related_families": ["Mozi", "Gafgyt", "Satori", "Okiru", "Masuta", "Muhstik"],
        "references": [
            "https://krebsonsecurity.com/2016/10/who-makes-the-iot-things-under-attack/",
            "https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-antonakakis.pdf",
            "https://malpedia.caad.fkie.fraunhofer.de/details/elf.mirai",
        ],

        "analyst_notes": (
            "Any Mirai detection indicates an internet-exposed IoT device with "
            "default or weak credentials. Immediate actions: isolate device, "
            "change all credentials, update firmware, block port 23/2323 inbound."
        ),
    },

    "gafgyt": {
        "actor_name":    "Multiple operators (leaked source code)",
        "actor_id":      "TA-GAFGYT-001",
        "also_known_as": ["BASHLITE", "Qbot", "Lizkebab", "Torlus", "LizardStresser"],
        "origin":        "Unknown (Lizard Squad associated with original)",
        "motivation":    ["DDoS-for-hire", "Financial"],
        "active_since":  "2014",
        "active_until":  "Ongoing",
        "status":        "ACTIVE — source code leaked 2015, many active variants",
        "threat_level":  "HIGH",

        "description": (
            "Gafgyt/BASHLITE is one of the oldest IoT botnets, predating Mirai. "
            "Source code leaked in 2015. Associated with Lizard Squad's DDoS-for-hire "
            "service (LizardStresser). Targets Linux/IoT devices via brute-force. "
            "Known for embedding large credential lists directly in the binary."
        ),

        "targeted_sectors":  ["Gaming", "Hosting", "IoT Devices", "Telecom"],
        "targeted_regions":  ["Global"],

        "capabilities": [
            "UDP/TCP/HTTP DDoS floods",
            "Telnet brute-forcing with embedded credential list",
            "Scanner for vulnerable devices",
            "HOLD/JUNK/UDP/TCP/HTTP attack commands",
            "Remote shell access",
        ],

        "exploited_cves": [
            {"cve": "CVE-2014-8361", "description": "Realtek SDK UPnP RCE", "severity": "HIGH"},
        ],

        "mitre_techniques": [
            {"id": "T1078.001","name": "Default Credentials",          "tactic": "Initial Access"},
            {"id": "T1059.004","name": "Unix Shell",                   "tactic": "Execution"},
            {"id": "T1498",    "name": "Network Denial of Service",    "tactic": "Impact"},
            {"id": "T1046",    "name": "Network Service Scanning",     "tactic": "Discovery"},
        ],

        "ioc_patterns": [
            "PING/PONG keepalive traffic to C2",
            "Hardcoded credential list in binary (vizxv, xc3511, hi3518)",
            "SCANNER ON/OFF commands over TCP",
            "KILLATTK command to stop attack",
            "Binary containing LOLNOGTFO string",
        ],

        "infrastructure": {
            "c2_protocol":  "Custom plaintext TCP",
            "c2_ports":     ["1024-65535 (variable)"],
            "persistence":  ["rc.local", "crontab"],
            "drop_paths":   ["/tmp/", "/var/run/"],
        },

        "related_families": ["Mirai", "Mozi", "Tsunami"],
        "references": [
            "https://malpedia.caad.fkie.fraunhofer.de/details/elf.gafgyt",
            "https://unit42.paloaltonetworks.com/unit42-torlus-botnet/",
        ],

        "analyst_notes": (
            "Gafgyt detection indicates a device with default Telnet credentials. "
            "The embedded credential list (vizxv, xc3511, etc.) are factory defaults "
            "for IP cameras and DVRs. Isolate, reflash firmware, disable Telnet."
        ),
    },
}

# ─────────────────────────────────────────────────────────────────
# NORMALISE ALIASES  (so "mirai/satori", "bashlite" etc. all resolve)
# ─────────────────────────────────────────────────────────────────
FAMILY_ALIASES = {
    # Mirai variants
    "mirai":        "mirai",
    "satori":       "mirai",
    "okiru":        "mirai",
    "masuta":       "mirai",
    "muhstik":      "mirai",
    "sylveon":      "mirai",
    # Mozi
    "mozi":         "mozi",
    # Gafgyt variants
    "gafgyt":       "gafgyt",
    "bashlite":     "gafgyt",
    "qbot":         "gafgyt",
    "lizkebab":     "gafgyt",
    "torlus":       "gafgyt",
    "lizardstresser": "gafgyt",
}


def resolve_family(family_name: str) -> str:
    """Normalise a family name to the canonical key in THREAT_ACTORS."""
    if not family_name:
        return ""
    key = family_name.lower().strip()
    # Direct match
    if key in THREAT_ACTORS:
        return key
    # Alias match
    if key in FAMILY_ALIASES:
        return FAMILY_ALIASES[key]
    # Partial match (e.g. "Mirai.Satori" → "mirai")
    for alias, canonical in FAMILY_ALIASES.items():
        if alias in key:
            return canonical
    return ""


# ─────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def map_threat_actor(family: str, metadata: dict = None) -> dict:
    """
    Main function called by app.py.

    Args:
        family:   malware family name from Bazaar/YARA (e.g. "Mozi")
        metadata: optional Bazaar metadata dict for enrichment

    Returns full threat actor profile dict with status field.
    """
    metadata = metadata or {}
    canonical = resolve_family(family)

    if not canonical:
        return {
            "status":      "unknown",
            "message":     f"No threat actor data for family: '{family}'",
            "family_input": family,
            "actor_name":  "Unknown",
            "threat_level": "UNKNOWN",
        }

    profile = THREAT_ACTORS[canonical].copy()

    # Enrich with metadata signals
    enrichment = {}

    # Check if tags corroborate the family
    tags = [t.lower() for t in metadata.get("tags", [])]
    family_lower = family.lower()
    if family_lower in tags:
        enrichment["tag_corroboration"] = True
        enrichment["confidence_boost"]  = "+10 (family confirmed in Bazaar tags)"
    else:
        enrichment["tag_corroboration"] = False

    # Flag if sample is recent (< 6 months old = active campaign)
    first_seen = metadata.get("first_seen", "")
    if first_seen:
        try:
            from datetime import datetime
            fs = datetime.strptime(first_seen[:10], "%Y-%m-%d")
            days_old = (datetime.utcnow() - fs).days
            if days_old < 180:
                enrichment["campaign_recency"] = "RECENT"
                enrichment["days_since_first_seen"] = days_old
            else:
                enrichment["campaign_recency"] = "HISTORICAL"
                enrichment["days_since_first_seen"] = days_old
        except Exception:
            pass

    # Architecture hint from TLSH / file_type
    file_type = metadata.get("file_type", "")
    enrichment["file_type"] = file_type

    profile["status"]      = "found"
    profile["canonical_family"] = canonical
    profile["family_input"] = family
    profile["enrichment"]  = enrichment

    print(f"[ThreatMap] Mapped '{family}' → {profile['actor_name']} (threat_level: {profile['threat_level']})")
    return profile