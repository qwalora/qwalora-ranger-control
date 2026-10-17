"""S3/S4 - STRATA board scenario VARIANTS (structural portfolios).

A variant is an approved, candidate-safe STRUCTURAL definition of a board scenario: it selects the
actual technical content the generator produces (technique pools, kill chains, incident families,
benign look-alikes), so two cohorts assigned different variants face materially different
assessments, not the same challenge with renamed hosts/seeds. Variants are deterministic inputs to
the existing generators (scenarios.generate_boardN for boards 1/3/4; siem.enterprise.generate for
board 2); they do not fork the generator or create a parallel platform.

Each variant declares:
  * gen_params     - what the generator consumes (pools / families / chains)
  * diversity      - the MATERIAL axes that make it different (never identifiers/timestamps/seeds),
                     used by the strengthened material-diversity check
  * competencies   - the board competencies it exercises (for parity checking)
  * difficulty     - the intended difficulty band (verified by calibration, not trusted)
  * business_context - candidate-safe mission framing (NO hidden family, truth, or attack path)

Protected truth is never stored here: the generator recomputes it from the seed server-side. The
`business_context` is written so it does not reveal the hidden incident family or solve the case.
"""
from __future__ import annotations

# --- Board 1: SOC alert triage -------------------------------------------------------------
# tp_techniques tuples format with {n} {m} {src} {dst} {user} {d}; benign pools format with
# {user} {dst} {d}. Different pools => different attack behaviors, technique distributions and
# false-positive look-alike patterns per cohort.
_B1_CRED = [
    ("T1110.003", "Password Spraying",
     "{n} failed NTLM logons across {m} accounts from {src} in 4 min, then 1 success for {user}"),
    ("T1078", "Valid Accounts",
     "Interactive logon for {user} from {src} at 03:1{d} (off-hours, no prior auth history)"),
    ("T1110.001", "Password Guessing",
     "{n} failed RDP logons for {user} from {src}, then one success"),
    ("T1558.003", "Kerberoasting",
     "TGS-REQ for {m} service principals from {user} on {src}, RC4 tickets requested in a burst"),
]
_B1_EXEC = [
    ("T1053.005", "Scheduled Task",
     "Scheduled task 'Updater' created on {dst} by {user} running a base64 powershell payload"),
    ("T1047", "Windows Management Instrumentation",
     "wmiprvse spawned cmd.exe on {dst} via remote WMI from {src} as {user}"),
    ("T1543.003", "New Service",
     "Service 'WinHelpSvc' created on {dst} by {user}, binary path under C:\\ProgramData"),
    ("T1059.001", "PowerShell",
     "powershell.exe -enc (hidden) on {dst} by {user}, parent process winword.exe"),
]
_B1_LATERAL = [
    ("T1021.002", "SMB / Admin Shares",
     "ADMIN$ share access on {dst} by {user} from {src}, followed by service creation"),
    ("T1021.001", "Remote Desktop",
     "RDP session {src} -> {dst} as {user} at 02:{d}, outside business hours"),
    ("T1074.001", "Local Data Staging",
     "{m}00 MB archived to C:\\ProgramData\\{user}.zip on {dst}"),
    ("T1048", "Exfiltration Over Alternative Protocol",
     "{m}00 MB uploaded from {dst} to external host {src} over HTTPS in one session"),
]
_B1_BENIGN_AUTH = [
    "VPN login for {user} from a known corporate IP",
    "Password change for {user} via self-service portal",
    "MFA re-enrollment for {user} after device swap",
    "Account {user} unlocked by service desk",
]
_B1_BENIGN_EXEC = [
    "Windows Update installed KB50{d}321 on {dst}",
    "Scheduled backup job completed on {dst}",
    "GoogleUpdate service task ran on {dst}",
    "SCCM software deployment to {dst} completed",
]
_B1_BENIGN_LATERAL = [
    "{user} mapped network drive to \\\\{dst}\\shared",
    "Nightly file sync from {dst} to the backup share completed",
    "Helpdesk RDP to {dst} during a scheduled maintenance window",
    "Large legitimate export from reporting job on {dst}",
]

# --- Board 3: detection engineering (technique subsets from the expanded catalog) ----------
_B3_EXEC_C2 = ["T1059.001", "T1105", "T1047", "T1053.005", "T1071.001", "T1048.003"]
_B3_CRED_IDENTITY = ["T1003.001", "T1003.002", "T1087.002", "T1136.001", "T1552.001", "T1569.002"]
_B3_EVASION_IMPACT = ["T1562.001", "T1490", "T1105", "T1003.002", "T1053.005", "T1047"]

# --- Board 4: IR kill chains (declarative step templates) ----------------------------------
# step: (technique, event_type, host_role, acct_role, detail_template, is_persistence)
_B4_CHAIN_RDP_SCHTASK = [
    ("T1059.001", "process", "pz", "u1", "powershell.exe -nop -w hidden -enc JAB{tok}== on {pz}", False),
    ("T1087.002", "process", "pz", "u1", 'net.exe group "Domain Admins" /domain on {pz}', False),
    ("T1003.001", "process", "pz", "u1", "rundll32.exe comsvcs.dll MiniDump lsass -> {tok}.dmp on {pz}", False),
    ("T1021.002", "auth", "dst", "u2", "ADMIN$ logon to {dst} as {u2acct} from {pz}, then service create", False),
    ("T1053.005", "process", "dst", "u2", "schtasks /create /ru SYSTEM /tn 'EdgeUpdateX' /tr powershell on {dst}", True),
    ("T1071.001", "network", "dst", "u2", "{dst} -> {c2}:443 HTTPS beacon every 60s, 8h", False),
    ("T1048.003", "dns", "dst", "u2", "{dst} -> {c2} 200+ TXT lookups, ~2MB exfil", False),
]
_B4_CHAIN_WEBSHELL_SERVICE = [
    ("T1059.003", "process", "pz", "u1", "w3wp.exe spawned cmd.exe /c whoami on {pz} (webshell)", False),
    ("T1136.001", "process", "pz", "u1", "net.exe user svc_{tok} /add then /add to Administrators on {pz}", False),
    ("T1003.002", "process", "pz", "u1", "reg.exe save HKLM\\SAM C:\\ProgramData\\{tok}.sav on {pz}", False),
    ("T1047", "process", "dst", "u2", "wmic /node:{dst} process call create 'cmd /c {tok}.bat' from {pz}", False),
    ("T1543.003", "process", "dst", "u2", "sc.exe create WinHelpSvc binPath= c:\\{tok}.exe start= auto on {dst}", True),
    ("T1071.001", "network", "dst", "u2", "{dst} -> {c2}:443 HTTPS POST uploads, 90 MB over 2h", False),
]
_B4_CHAIN_VPN_REGISTRY = [
    ("T1059.001", "process", "pz", "u1", "powershell.exe -enc download cradle on {pz}", False),
    ("T1558.003", "process", "pz", "u1", "Rubeus-style TGS requests for {m} SPNs on {pz}", False),
    ("T1021.002", "auth", "dst", "u2", "SMB logon to {dst} as {u2acct} from {pz}", False),
    ("T1547.001", "process", "dst", "u2", "reg.exe add ...\\Run /v Updater /d c:\\{tok}.exe on {dst}", True),
    ("T1048.003", "dns", "dst", "u2", "{dst} -> {c2} DNS TXT tunnel, high-entropy labels, ~3MB", False),
]
# board-4 initial-access vector pools (tid, name, event_type, template with {tok}{H}{U}{d})
_B4_VEC_PHISH = [("T1566.001", "Spearphishing Attachment", "process",
                  "winword.exe opened invoice_{tok}.docm then spawned powershell.exe -enc on {H} ({U})")]
_B4_VEC_WEBAPP = [("T1190", "Exploit Public-Facing Application", "process",
                   "w3wp.exe on {H} spawned cmd.exe after POST /upload.aspx (webshell dropped) by {U}")]
_B4_VEC_VPN = [("T1078", "Valid Accounts", "auth",
                "VPN + interactive logon for {U} from external 203.0.113.{d} to {H}, no MFA challenge")]


# ============================ the variant registry =========================================
VARIANTS = {
    1: {
        "b1-credential-access": {
            "title": "Credential-access alert queue",
            "difficulty": "standard",
            "competencies": ["verdict", "severity", "technique_attribution", "ioc_extraction"],
            "diversity": {"attack_theme": "credential-access",
                          "techniques": sorted(t[0] for t in _B1_CRED),
                          "fp_pattern": "authentication-lookalikes"},
            "business_context": "An overnight queue dominated by authentication and access-control "
                                "alerts across the corporate estate. Adjudicate which represent "
                                "genuine credential abuse and which are routine access noise.",
            "gen_params": {"id": "b1-credential-access", "tp_techniques": _B1_CRED,
                           "benign": _B1_BENIGN_AUTH, "tp_count": (4, 7)},
        },
        "b1-execution-persistence": {
            "title": "Endpoint execution and persistence queue",
            "difficulty": "standard",
            "competencies": ["verdict", "severity", "technique_attribution", "ioc_extraction"],
            "diversity": {"attack_theme": "execution-persistence",
                          "techniques": sorted(t[0] for t in _B1_EXEC),
                          "fp_pattern": "software-deployment-lookalikes"},
            "business_context": "A queue of endpoint execution and persistence alerts. Separate "
                                "genuine attacker execution from legitimate software deployment and "
                                "scheduled maintenance.",
            "gen_params": {"id": "b1-execution-persistence", "tp_techniques": _B1_EXEC,
                           "benign": _B1_BENIGN_EXEC, "tp_count": (4, 7)},
        },
        "b1-lateral-exfil": {
            "title": "Lateral movement and exfiltration queue",
            "difficulty": "advanced",
            "competencies": ["verdict", "severity", "technique_attribution", "ioc_extraction"],
            "diversity": {"attack_theme": "lateral-exfiltration",
                          "techniques": sorted(t[0] for t in _B1_LATERAL),
                          "fp_pattern": "file-transfer-lookalikes"},
            "business_context": "A queue weighted toward lateral movement and data movement. "
                                "Distinguish genuine lateral access and exfiltration from "
                                "legitimate file transfers and remote administration.",
            "gen_params": {"id": "b1-lateral-exfil", "tp_techniques": _B1_LATERAL,
                           "benign": _B1_BENIGN_LATERAL, "tp_count": (4, 7)},
        },
    },
    2: {
        "b2-identity-takeover": {
            "title": "Privileged identity takeover investigation",
            "difficulty": "advanced",
            "competencies": ["incident_scoping", "evidence_citation", "timeline", "detection_gap"],
            "diversity": {"objective": "privileged-identity-abuse",
                          "families": sorted(["privileged-identity-compromise",
                                              "endpoint-lateral-movement", "data-exfiltration"]),
                          "detection_gaps": [], "boundary": "identity-and-datacenter"},
            "business_context": "Investigate suspected abuse of privileged identities and lateral "
                                "progression across the enterprise within the assessment window.",
            "gen_params": {"families": ["privileged-identity-compromise", "endpoint-lateral-movement",
                                        "data-exfiltration"], "profile": "B"},
        },
        "b2-insider-exfil": {
            "title": "Service-account misuse and exfiltration investigation",
            "difficulty": "advanced",
            "competencies": ["incident_scoping", "evidence_citation", "timeline", "detection_gap"],
            "diversity": {"objective": "data-exfiltration",
                          "families": sorted(["compromised-service-identity", "data-exfiltration",
                                              "detection-failure"]),
                          "detection_gaps": ["detection-failure"], "boundary": "datacenter-and-dmz"},
            "business_context": "Investigate anomalous service-account behavior and potential data "
                                "exfiltration, including whether current detections covered it.",
            "gen_params": {"families": ["compromised-service-identity", "data-exfiltration",
                                        "detection-failure"], "profile": "B"},
        },
        "b2-stealth-lateral": {
            "title": "Stealth lateral-movement investigation",
            "difficulty": "advanced",
            "competencies": ["incident_scoping", "evidence_citation", "timeline", "detection_gap"],
            "diversity": {"objective": "endpoint-lateral-movement",
                          "families": sorted(["endpoint-lateral-movement",
                                              "compromised-service-identity",
                                              "privileged-identity-compromise"]),
                          "detection_gaps": [], "boundary": "corp-and-datacenter"},
            "business_context": "Investigate suspected hands-on-keyboard lateral movement across "
                                "workstations and servers within the assessment window.",
            "gen_params": {"families": ["endpoint-lateral-movement", "compromised-service-identity",
                                        "privileged-identity-compromise"], "profile": "B"},
        },
    },
    3: {
        "b3-execution-c2": {
            "title": "Execution and command-and-control detection set",
            "difficulty": "standard",
            "competencies": ["coverage", "precision", "generalization"],
            "diversity": {"detection_domain": "execution-c2", "techniques": sorted(_B3_EXEC_C2)},
            "business_context": "Author detections for an execution-to-C2 behavior set. Your rules "
                                "must generalize to unseen variants and stay quiet on legitimate "
                                "administrative use of the same tools.",
            "gen_params": {"id": "b3-execution-c2", "techniques": _B3_EXEC_C2},
        },
        "b3-credential-identity": {
            "title": "Credential-access and identity detection set",
            "difficulty": "advanced",
            "competencies": ["coverage", "precision", "generalization"],
            "diversity": {"detection_domain": "credential-identity",
                          "techniques": sorted(_B3_CRED_IDENTITY)},
            "business_context": "Author detections for credential-access and identity-manipulation "
                                "behaviors. Coverage across the whole set and precision against "
                                "legitimate administration are both required.",
            "gen_params": {"id": "b3-credential-identity", "techniques": _B3_CRED_IDENTITY},
        },
        "b3-evasion-impact": {
            "title": "Defense-evasion and impact detection set",
            "difficulty": "advanced",
            "competencies": ["coverage", "precision", "generalization"],
            "diversity": {"detection_domain": "evasion-impact",
                          "techniques": sorted(_B3_EVASION_IMPACT)},
            "business_context": "Author detections for defense-evasion and impact behaviors. Avoid "
                                "false positives on legitimate maintenance that resembles them.",
            "gen_params": {"id": "b3-evasion-impact", "techniques": _B3_EVASION_IMPACT},
        },
    },
    4: {
        "b4-phish-rdp-schtask": {
            "title": "Phishing to scheduled-task persistence",
            "difficulty": "standard",
            "competencies": ["patient_zero", "initial_access", "scope", "timeline", "persistence"],
            "diversity": {"initial_access": "T1566.001", "persistence": "T1053.005",
                          "lateral": "T1021.002",
                          "chain": [s[0] for s in _B4_CHAIN_RDP_SCHTASK]},
            "business_context": "Reconstruct a breach that began with a phishing document and "
                                "progressed to persistence and exfiltration. Scope it and order the "
                                "events from the forensic evidence.",
            "gen_params": {"id": "b4-phish-rdp-schtask", "vectors": _B4_VEC_PHISH,
                           "chain": _B4_CHAIN_RDP_SCHTASK, "use_third": True},
        },
        "b4-webshell-service": {
            "title": "Webshell to service persistence",
            "difficulty": "advanced",
            "competencies": ["patient_zero", "initial_access", "scope", "timeline", "persistence"],
            "diversity": {"initial_access": "T1190", "persistence": "T1543.003",
                          "lateral": "T1047",
                          "chain": [s[0] for s in _B4_CHAIN_WEBSHELL_SERVICE]},
            "business_context": "Reconstruct a breach that began with exploitation of a public-facing "
                                "application. Determine the entry point, scope, order and the "
                                "persistence that must be removed.",
            "gen_params": {"id": "b4-webshell-service", "vectors": _B4_VEC_WEBAPP,
                           "chain": _B4_CHAIN_WEBSHELL_SERVICE, "use_third": False},
        },
        "b4-vpn-registry": {
            "title": "Valid-account VPN to registry persistence",
            "difficulty": "advanced",
            "competencies": ["patient_zero", "initial_access", "scope", "timeline", "persistence"],
            "diversity": {"initial_access": "T1078", "persistence": "T1547.001",
                          "lateral": "T1021.002",
                          "chain": [s[0] for s in _B4_CHAIN_VPN_REGISTRY]},
            "business_context": "Reconstruct a breach that began with valid-account remote access. "
                                "Identify the account path, scope the compromise, order the timeline "
                                "and find the persistence mechanism.",
            "gen_params": {"id": "b4-vpn-registry", "vectors": _B4_VEC_VPN,
                           "chain": _B4_CHAIN_VPN_REGISTRY, "use_third": True},
        },
    },
    # --- Board 5 (Raider): single-domain GOAD AD red-team families. Material diversity is in the
    # attack PATH: which identities are roastable, which dangerous ACL edge is the escalation, and
    # the pivot host - not reshuffled names. Any two families differ on >= 2 declared axes.
    5: {
        "b5-kerberoast-genericall": {
            "title": "Raider: service-ticket path",
            "difficulty": "standard",
            "competencies": ["ad-recon", "kerberoast", "acl-abuse", "lateral-movement", "dcsync"],
            "business_context": "An authorized adversarial assessment of a single Active Directory "
                                "domain. Establish a foothold, escalate through a dangerous ACL edge, "
                                "and reach domain dominance with cited, reproducible evidence.",
            "diversity": {"escalation_edge": "GenericAll", "roastable": "service-accounts",
                          "lateral": "castelblack", "initial_access": "password-spray"},
            "gen_params": {"id": "b5-kerberoast-genericall",
                           "svc_pool": ["sql_svc", "http_svc"],
                           "asrep_pool": ["brandon.stark", "missandei", "jon.snow", "samwell.tarly"],
                           "lateral_pool": ["castelblack"], "escalation_edge": "GenericAll"},
        },
        "b5-asrep-writedacl": {
            "title": "Raider: pre-auth path",
            "difficulty": "standard",
            "competencies": ["ad-recon", "asrep-roast", "acl-abuse", "lateral-movement", "dcsync"],
            "business_context": "An authorized adversarial assessment of a single Active Directory "
                                "domain where pre-authentication weaknesses open the initial path to "
                                "privilege. Escalate and reach domain dominance with evidence.",
            "diversity": {"escalation_edge": "WriteDACL", "roastable": "asrep-users",
                          "lateral": "meereen", "initial_access": "asrep-roast"},
            "gen_params": {"id": "b5-asrep-writedacl",
                           "svc_pool": ["backup_svc", "web_svc"],
                           "asrep_pool": ["brandon.stark", "missandei"],
                           "lateral_pool": ["meereen"], "escalation_edge": "WriteDACL"},
        },
        "b5-delegation-forcechange": {
            "title": "Raider: delegation path",
            "difficulty": "advanced",
            "competencies": ["ad-recon", "kerberoast", "targeted-acl", "lateral-movement", "dcsync"],
            "business_context": "An authorized adversarial assessment of a single Active Directory "
                                "domain where a targeted account-control edge is the escalation. "
                                "Reach domain dominance with cited, reproducible evidence.",
            "diversity": {"escalation_edge": "ForceChangePassword", "roastable": "mixed-identities",
                          "lateral": "castelblack", "initial_access": "targeted-kerberoast"},
            "gen_params": {"id": "b5-delegation-forcechange",
                           "svc_pool": ["sql_svc", "web_svc"],
                           "asrep_pool": ["jon.snow", "samwell.tarly"],
                           "lateral_pool": ["castelblack"], "escalation_edge": "ForceChangePassword"},
        },
    },
    # --- Board 6 (Vanguard): multi-forest capstone families. Material diversity is in the trust
    # TOPOLOGY to cross, where the crown jewels live, and the escalation technique. Every family is
    # unique on all four declared axes.
    6: {
        "b6-child-parent-sidhistory": {
            "title": "Vanguard: child-to-parent capstone",
            "difficulty": "advanced",
            "competencies": ["forest-recon", "trust-abuse", "sid-history", "forest-persistence",
                             "cross-forest"],
            "business_context": "An authorized multi-domain capstone. Own a child domain, abuse the "
                                "child-to-parent trust to seize the forest, and establish defensible, "
                                "evidence-backed conclusions across the estate.",
            "diversity": {"trust_topology": "child-to-parent", "crown_location": "parent-dc",
                          "escalation": "SID-history", "initial_access": "child-spray"},
            "gen_params": {"id": "b6-child-parent-sidhistory", "forest2_host_pool": ["castelblack"],
                           "trust_topology": "child-to-parent", "crown_location": "parent-dc",
                           "escalation": "SID-history"},
        },
        "b6-crossforest-trustkey": {
            "title": "Vanguard: cross-forest capstone",
            "difficulty": "advanced",
            "competencies": ["forest-recon", "trust-key", "cross-forest", "forest-persistence",
                             "exfiltration"],
            "business_context": "An authorized multi-forest capstone. Pivot across a forest trust to "
                                "compromise a second forest and recover the crown jewels with cited, "
                                "reproducible evidence.",
            "diversity": {"trust_topology": "cross-forest", "crown_location": "forest2-dc",
                          "escalation": "trust-key", "initial_access": "forest-roast"},
            "gen_params": {"id": "b6-crossforest-trustkey", "forest2_host_pool": ["meereen"],
                           "trust_topology": "cross-forest", "crown_location": "forest2-dc",
                           "escalation": "trust-key"},
        },
        "b6-bidirectional-golden": {
            "title": "Vanguard: forest-persistence capstone",
            "difficulty": "advanced",
            "competencies": ["forest-recon", "golden-ticket", "forest-persistence", "cross-forest",
                             "exfiltration"],
            "business_context": "An authorized multi-forest capstone emphasising forest-wide "
                                "persistence and recovery analysis. Seize the forest, establish "
                                "persistence, and defend your conclusions with evidence.",
            "diversity": {"trust_topology": "bidirectional", "crown_location": "root-dc",
                          "escalation": "golden-ticket", "initial_access": "kerberoast-first"},
            "gen_params": {"id": "b6-bidirectional-golden",
                           "forest2_host_pool": ["castelblack", "meereen"],
                           "trust_topology": "bidirectional", "crown_location": "root-dc",
                           "escalation": "golden-ticket"},
        },
    },
}

# Boards whose variants the catalog registers by default. Boards 5/6 are registered explicitly in
# Part 2 once their catalog/spec/simulate arms land; adding them here before that would make the
# default register_all() try to simulate a board it cannot build yet.
PORTFOLIO_BOARDS = (1, 2, 3, 4)


def variants_for(board):
    """All variant ids defined for a board (deterministic order)."""
    return sorted(VARIANTS.get(int(board), {}))


def get(board, variant_id):
    """The full variant definition, or None."""
    return VARIANTS.get(int(board), {}).get(variant_id)


def gen_params(board, variant_id):
    """The deterministic parameters the generator consumes for this variant, or None."""
    v = get(board, variant_id)
    return dict(v["gen_params"]) if v else None


def diversity_axes(board, variant_id):
    v = get(board, variant_id)
    return dict(v["diversity"]) if v else {}


def competencies(board, variant_id):
    v = get(board, variant_id)
    return list(v.get("competencies", [])) if v else []


def difficulty(board, variant_id):
    v = get(board, variant_id)
    return v.get("difficulty") if v else None


def business_context(board, variant_id):
    v = get(board, variant_id)
    return v.get("business_context") if v else None


def title(board, variant_id):
    v = get(board, variant_id)
    return v.get("title") if v else None
