"""Ranger Cohort Readiness & Technical Knowledge publications (Collection 2).

Original Qwalora documentation and technical-methodology references. These make
no experimental claims: commands shown are illustrative and are never labeled
tested or verified without an execution record. Ludus/GOAD are documented as
planned Ranger infrastructure, not operational, until verified in production.

Published incrementally under the same admin-managed system as the research
portfolio; attribution is Qwalora throughout.
"""

PUBLISHER = "Qwalora LLC, Ranger program"


def _mv(note=None):
    """Verification block for a documentation / methodology publication. It
    states plainly that no experiment is claimed, so the article does not imply
    executed research."""
    return {
        "execution": {"status": "not-applicable (reference documentation)",
                      "environment": "Original Qwalora technical documentation"},
        "independent_verification": {
            "performed": False,
            "method": note or ("Reviewed technical documentation and methodology. It makes no "
                               "experimental claims. Commands and configurations shown are "
                               "illustrative and are not labeled tested or verified unless an "
                               "execution record supports that claim."),
            "trust_boundary": "n/a"},
        "review": {"technical_status": "pending_technical_review", "approved_by": None, "approved_at": None},
    }


PUBLICATIONS = [
    # ---- Ranger Cohort & Qualification Documentation -----------------------
    {
        "pub_id": "QR-DOC-001",
        "slug": "ranger-cohort-architecture",
        "title": "Ranger Cohort Architecture",
        "track": "cohort-docs", "collection": "Ranger Cohort & Qualification Documentation",
        "category": "frameworks", "rtype": "technical-documentation", "level": "foundational",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Program architecture, Boards, Assessment, Evidence",
        "source_attribution": PUBLISHER,
        "related": "QR-DOC-002,QR-RES-002",
        "refs": [
            {"label": "MITRE ATT&CK (adversary tactics and techniques)", "url": "https://attack.mitre.org/"},
            {"label": "NIST SP 800-181r1: Workforce Framework for Cybersecurity (NICE)",
             "url": "https://csrc.nist.gov/pubs/sp/800/181/r1/final"},
        ],
        "verification": _mv(),
        "summary": "How the Qwalora Ranger program is built: a documentation-driven, independent-work "
        "qualification with six boards, two grading channels, and cryptographically signed evidence. "
        "This reference explains the professional standard Ranger holds, how boards progress from SOC "
        "analysis to a capstone, what candidates produce and how it is assessed, and the role of "
        "prerequisites. It states the Ranger Scholars access arrangement plainly and does not disclose "
        "qualification tests, grading logic, or solutions.",
        "body": r"""## What Ranger is

Qwalora Ranger is a verifiable cyber-range qualification, not a tutorial site. A
candidate progresses through six boards by doing independent, documentation-driven
technical work and producing evidence that is graded against a fixed standard. The
program is operated as part of Qwalora's security research practice.

## The professional standard

Ranger assumes professional competence and verifies it under realistic conditions.
Work is done the way it is done on the job: from vendor and standards documentation,
on real tooling, without step-by-step hand-holding. A candidate who needs a guided
beginner course is not yet ready for Ranger.

**Linux proficiency is a strict prerequisite.** Ranger does not teach introductory
Linux. A candidate is expected to administer a Linux system, navigate the shell and
filesystem, manage services and permissions, and read logs before admission. The
technical prerequisites are documented separately (see Ranger Technical Prerequisites).

## Board progression

The program is organized as six boards that move from defensive triage to offensive
operations and a capstone:

- Board 1, Sentinel: security operations and alert triage.
- Board 2, Tracker: threat hunting.
- Board 3, Warden: detection engineering.
- Board 4, Reclaimer: incident response and reconstruction.
- Board 5, Raider: offensive operations and adversary emulation.
- Board 6, Vanguard: a capstone that integrates the prior disciplines.

Each board has a role and a clearance. Progression is earned by clearing the board,
not by time served.

## Two grading channels

Every board is graded on two independent channels. An objective channel measures
technical outcomes in a reproducible, answer-free way: the program re-measures the
candidate's result rather than comparing against a stored answer key, so there is no
answer to leak. A subjective channel is a human review of the candidate's written
analysis and reasoning. A board clears only when both channels are satisfied.

## Signed evidence

When a board clears, Ranger mints a cryptographically signed clearance and, at the
end, a signed certificate. Signing uses Ed25519, and anyone can verify a credential
in the browser against the published public key. A rank cannot be self-reported: the
signature is the proof. The same evidence discipline underlies Qwalora's research
publications, where observations are signed and bound to the run that produced them.

## Technical deliverables

A candidate's output is technical work product: written investigations, detection
logic and its rationale, reconstructed timelines, and operational narratives. The
deliverables are the artifacts a working practitioner produces, reviewed to the
standard a working practitioner is held to.

## Ranger Scholars

Ranger Scholars is a sponsor-funded access arrangement that lets qualified candidates
aged 13 and over take the same program at no cost to them. It is **not** a separate
platform and **not** a simplified curriculum. A Scholar sits the same boards, meets the
same prerequisites, and is graded to the same standard as any other candidate.

## What this document does not contain

This reference describes the program's architecture. It does not disclose the
confidential qualification tests, the internal grading logic, candidate data, or any
unpublished solution. Those are not public and are not part of the knowledge base.

""",
    },
    {
        "pub_id": "QR-DOC-002",
        "slug": "ranger-technical-prerequisites",
        "title": "Ranger Technical Prerequisites",
        "track": "cohort-docs", "collection": "Core Technical Prerequisites",
        "category": "linux-sysadmin", "rtype": "technical-documentation", "level": "foundational",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Prerequisites, Linux, Networking, Automation, Windows",
        "source_attribution": PUBLISHER,
        "related": "QR-DOC-001,QR-KB-005",
        "refs": [
            {"label": "The Linux Documentation Project / man-pages", "url": "https://man7.org/linux/man-pages/"},
            {"label": "RFC 9293: Transmission Control Protocol", "url": "https://www.rfc-editor.org/rfc/rfc9293"},
            {"label": "Pro Git (git-scm.com)", "url": "https://git-scm.com/book/en/v2"},
            {"label": "Microsoft Learn: Windows Server documentation",
             "url": "https://learn.microsoft.com/en-us/windows-server/"},
        ],
        "verification": _mv(),
        "summary": "The baseline a candidate must already hold before Ranger: Linux administration and "
        "troubleshooting; networking, DNS, TCP/IP, routing and network analysis; Bash, Python, Git and "
        "engineering automation; and Windows administration with core Active Directory concepts. For each "
        "area it states the required competency, the architecture to understand, representative diagnostic "
        "commands, and a way to self-assess. It is a readiness standard, not a beginner course.",
        "body": r"""## How to read this

This is the competency baseline Ranger assumes on day one. Each area below states
what you must be able to do, the architecture to understand, representative commands,
and a self-assessment. The commands are illustrative of the fluency expected; they are
not a lesson. If any area reads as unfamiliar, close that gap before applying.

## 1. Linux administration and troubleshooting

Required: administer a Linux host without a GUI. Manage users, groups, permissions and
ownership; install and control services with systemd; read and follow logs; inspect
processes, open files and sockets; manage packages and storage.

Architecture: the filesystem hierarchy, process and permission model, systemd units
and journald, and the boot path.

Representative commands: `journalctl -u <svc> -f`, `systemctl status <svc>`,
`ss -tlnp`, `ps auxf`, `lsof -p <pid>`, `find / -perm -4000 -type f 2>/dev/null`,
`stat`, `chmod`/`chown`, `df -h`, `lsblk`.

Self-assessment: given a service that fails to start, can you diagnose it from logs and
unit state alone, and explain the cause, in minutes?

## 2. Networking, DNS, TCP/IP, routing, and network analysis

Required: reason about traffic at the packet and protocol level and diagnose
connectivity.

Architecture: the TCP/IP layers, addressing and subnetting, routing and the default
gateway, DNS resolution, TLS handshake basics, and how a request flows end to end.

Representative commands: `ip addr`, `ip route`, `ss -tan`, `dig +trace example.com`,
`tcpdump -ni any port 53`, `traceroute`, Wireshark display filters such as
`tcp.flags.syn==1 && tcp.flags.ack==0`.

Self-assessment: can you read a short packet capture and narrate the TCP handshake, a
DNS lookup, and where a failure occurred?

## 3. Bash, Python, Git, and engineering automation

Required: automate work and manage it under version control. Write a robust Bash
script and a small Python program; parse and transform text and JSON; use Git for real
branching and history.

Architecture: the shell execution and quoting model, exit codes and pipelines, Python
standard library for files, subprocess and JSON, and Git's commit/branch/remote model.

Representative commands: `set -euo pipefail`, `grep`/`sed`/`awk`, `jq`,
`python3 -c '...'`, `git rebase`, `git log --oneline --graph`, `git bisect`.

Self-assessment: can you turn a manual, multi-step task into a reproducible script with
error handling, and track it in Git with a clean history?

## 4. Windows administration and core Active Directory concepts

Required: operate Windows from PowerShell and understand the identity model that the
advanced boards build on.

Architecture: PowerShell and cmdlets, the Windows security model (SIDs, tokens,
privileges), the event log, and Active Directory Domain Services fundamentals (domain,
forest, organizational units, domain controllers, group policy). Understand how AD DS
differs from Microsoft Entra ID; the distinction is developed in the Active Directory
Security Engineering publications.

Representative commands: `Get-Service`, `Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624}`,
`whoami /all`, `Get-LocalUser`, and, on a domain-joined host, `Get-ADUser`, `Get-ADGroup`.

Self-assessment: can you query the Windows Security log for sign-in events and explain
what a logon type tells you, and describe what a domain controller is responsible for?

## Using this standard

Treat each self-assessment as a gate. Ranger's value is that it measures real capability;
arriving with these competencies is what lets the program measure security engineering
rather than operating-system basics.

""",
    },
    # ---- Active Directory Security Engineering ------------------------------
    {
        "pub_id": "QR-KB-010",
        "slug": "active-directory-domain-services-architecture",
        "title": "Active Directory Domain Services Architecture",
        "track": "knowledge-base", "collection": "Active Directory Security Engineering",
        "category": "offensive", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Active Directory, AD DS, Entra ID, Directory",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER,
        "related": "QR-KB-011,QR-KB-020",
        "refs": [
            {"label": "Microsoft Learn: Active Directory Domain Services overview",
             "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/get-started/virtual-dc/active-directory-domain-services-overview"},
            {"label": "Microsoft Learn: Compare AD DS, Entra ID, and Entra Domain Services",
             "url": "https://learn.microsoft.com/en-us/entra/architecture/auth-ad-overview"},
            {"label": "MITRE ATT&CK: Account Discovery (T1087)", "url": "https://attack.mitre.org/techniques/T1087/"},
        ],
        "verification": _mv(),
        "summary": "The architecture of Active Directory Domain Services: domains, trees, forests, "
        "organizational units, domain controllers, the global catalog, FSMO roles, multi-master "
        "replication, DNS and SYSVOL, and the schema. It distinguishes AD DS from Microsoft Entra ID and "
        "Entra Domain Services, shows representative read-only enumeration commands, and sets out the "
        "security implications, detection opportunities, and defensive controls for the directory that the "
        "advanced boards operate against.",
        "body": r"""## Scope and a necessary distinction

This reference covers **Active Directory Domain Services (AD DS)**, the on-premises
directory and authentication service. It is not Microsoft Entra ID (formerly Azure AD),
which is a cloud identity service using different protocols (OAuth 2.0, OpenID Connect,
SAML) rather than Kerberos and LDAP, and it is not Microsoft Entra Domain Services, a
managed domain in Azure. The three are related but architecturally distinct; Ranger's
advanced boards operate against AD DS.

## Logical structure

- **Domain:** a security and administrative boundary with a shared directory database.
- **Tree:** domains sharing a contiguous DNS namespace and a transitive trust.
- **Forest:** one or more trees sharing a schema, configuration, and global catalog;
  the forest, not the domain, is the security boundary.
- **Organizational unit (OU):** a container for delegation and Group Policy scoping.

## Physical and operational components

- **Domain controllers (DCs):** servers that host the directory (NTDS.dit), authenticate
  principals, and enforce policy.
- **Global catalog:** a partial, forest-wide index used for cross-domain lookups and
  logon.
- **FSMO roles:** five single-master operations (schema master, domain naming master,
  RID master, PDC emulator, infrastructure master) that are not multi-master.
- **Replication:** a multi-master model; most changes replicate between DCs, with the
  FSMO roles as the exceptions.
- **DNS and SYSVOL:** AD DS depends on DNS for locating services via SRV records, and
  SYSVOL distributes Group Policy and scripts.
- **Schema:** the definition of every object class and attribute in the forest.

## Representative read-only enumeration

These are illustrative of the directory's structure; they are read-only and not labeled
as tested here:

```
Get-ADForest
Get-ADDomain
Get-ADDomainController -Filter *
netdom query fsmo
Get-ADOrganizationalUnit -Filter * | Select-Object Name,DistinguishedName
dcdiag /v
repadmin /replsummary
```

## Security implications

The forest trust boundary matters: compromise of a domain can lead to the forest when
trust and replication are abused, and the directory is a rich reconnaissance target
(account, group, and trust discovery map to MITRE ATT&CK T1087 and related techniques).
Overbroad delegation, stale privileged accounts, and misconfigured trusts are the
recurring structural weaknesses.

## Detection opportunities

Directory reconnaissance and privileged changes are observable: Security event IDs for
account and group enumeration, directory service changes, and replication events (for
example DCSync-style replication from a non-DC principal) are the signals a detection
program watches.

## Defensive controls

Tier administrative access so that domain-controller credentials never touch lower-trust
hosts; minimize and monitor privileged group membership; constrain and audit delegation;
keep DCs patched and their event logs centralized; and treat the forest, not the domain,
as the security boundary when designing containment.

""",
    },
    {
        "pub_id": "QR-KB-011",
        "slug": "kerberos-authentication-and-detection",
        "title": "Kerberos Authentication and Detection",
        "track": "knowledge-base", "collection": "Active Directory Security Engineering",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Kerberos, NTLM, Authentication, Detection, ATT&CK",
        "board": 5, "role": "detection-engineer",
        "source_attribution": PUBLISHER,
        "related": "QR-KB-010,QR-RES-002",
        "refs": [
            {"label": "Microsoft Learn: Kerberos authentication overview",
             "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview"},
            {"label": "MITRE ATT&CK: Steal or Forge Kerberos Tickets (T1558)",
             "url": "https://attack.mitre.org/techniques/T1558/"},
            {"label": "MITRE ATT&CK: Use Alternate Authentication Material (T1550)",
             "url": "https://attack.mitre.org/techniques/T1550/"},
        ],
        "verification": _mv(
            "Reviewed technical documentation of the Kerberos protocol and its detection signals. "
            "Attack techniques are described at a conceptual and detection level, not as runnable "
            "exploitation tooling. Event IDs and controls are documented from vendor references, not "
            "labeled as tested here."),
        "summary": "How Kerberos authentication works in Active Directory and how to detect its abuse. "
        "It walks the AS and TGS exchanges, tickets, the KDC and the PAC, contrasts NTLM, and maps the "
        "common credential-access techniques (Kerberoasting, AS-REP roasting, forged tickets, delegation "
        "abuse) to their telemetry and Windows event IDs, with the defensive controls that reduce the "
        "attack surface. Techniques are described for detection, not as exploitation tooling.",
        "body": r"""## Why Kerberos

Kerberos is the primary authentication protocol in Active Directory. Understanding its
message flow is what makes its abuse detectable; most AD credential attacks are
deviations from the normal exchange rather than exotic exploits.

## The protocol, briefly

Three parties: the client, the Key Distribution Center (KDC, running on every domain
controller), and the service. Two exchanges:

1. **AS exchange (authentication):** the client requests a Ticket Granting Ticket (TGT)
   with AS-REQ; the KDC returns the TGT in AS-REP, encrypted with the krbtgt key, with a
   Privilege Attribute Certificate (PAC) carrying the user's group SIDs.
2. **TGS exchange (authorization):** the client presents the TGT and requests a service
   ticket for a Service Principal Name (SPN) with TGS-REQ; the KDC returns a service
   ticket in TGS-REP, encrypted with the target service account's key.
3. The client presents the service ticket to the service (AP-REQ).

NTLM is the older challenge-response fallback; it has no mutual authentication and is a
frequent downgrade target, so unexpected NTLM where Kerberos is expected is itself a
signal.

## Attack surface, at a detection level

- **Kerberoasting:** requesting service tickets for SPNs to crack weak service-account
  passwords offline. Signal: a principal requesting many TGS tickets, especially with RC4
  (etype 0x17). Maps to T1558.003.
- **AS-REP roasting:** requesting AS-REP for accounts with Kerberos pre-authentication
  disabled, to crack offline. Signal: AS-REQ without pre-auth for such accounts. T1558.004.
- **Golden ticket:** a forged TGT signed with a stolen krbtgt key. T1558.001.
- **Silver ticket:** a forged service ticket signed with a stolen service-account key.
- **Delegation abuse:** unconstrained, constrained, and resource-based constrained
  delegation can be abused to impersonate principals; maps to T1550.

These are described so they can be detected and defended, not as runnable tooling.

## Telemetry and event IDs

Windows Security log events carry the signals:

- 4768: a TGT was requested (AS exchange).
- 4769: a service ticket was requested (TGS exchange) - the core Kerberoasting signal.
- 4770: a service ticket was renewed.
- 4771: Kerberos pre-authentication failed.
- 4624/4625: logon success/failure, with logon type and authentication package.

Detection engineering watches for RC4 where AES is expected (encryption downgrade),
abnormal volumes or timing of 4769, SPN requests from unusual principals, and TGTs with
anomalous lifetimes.

## Defensive controls

Enforce AES and disable RC4 where possible; use long, random service-account passwords
or group Managed Service Accounts (gMSAs); rotate the krbtgt key (twice, with the
required interval) after suspected compromise; remove unnecessary SPNs and
pre-authentication exemptions; constrain and audit delegation; and centralize DC event
logs so the signals above are queryable.

""",
    },
    # ---- Ludus & GOAD Lab Architecture -------------------------------------
    {
        "pub_id": "QR-KB-020",
        "slug": "ludus-and-goad-environment-architecture",
        "title": "Ludus and GOAD Environment Architecture",
        "track": "knowledge-base", "collection": "Ludus & GOAD Lab Architecture",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Ludus, GOAD, Cyber range, Active Directory lab",
        "board": 5, "role": "red-teamer",
        "source_attribution": "Qwalora LLC. Ludus by Bad Sector Labs; GOAD by Orange Cyberdefense.",
        "related": "QR-KB-010,QR-KB-011",
        "refs": [
            {"label": "Ludus documentation", "url": "https://docs.ludus.cloud/"},
            {"label": "GOAD (Game of Active Directory), Orange Cyberdefense",
             "url": "https://github.com/Orange-Cyberdefense/GOAD"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(
            "Reviewed architecture documentation for the Ludus range platform and the GOAD lab. It "
            "describes third-party tooling and Qwalora's intended use of it. Ranger's own Ludus/GOAD "
            "environments are planned, not operational; nothing here is a claim that they are deployed in "
            "production, and no private lab solutions or board objectives are disclosed."),
        "summary": "The architecture of the Ludus range platform and the GOAD vulnerable Active Directory "
        "lab, and how Ranger intends to use them for its advanced boards. It covers Ludus provisioning, "
        "virtualization, network isolation and environment lifecycle, and GOAD's multi-domain identity "
        "attack surface and defensive research value. It states clearly which capabilities are planned "
        "rather than operational and credits both upstream projects.",
        "body": r"""## Status: planned, not yet operational

Ranger's blue boards run today on per-candidate datasets; the Ludus and GOAD
environments described here are **planned infrastructure for the advanced boards, not a
live production capability.** This document explains the intended architecture so that
candidates and reviewers understand what the advanced boards will require. Nothing here
asserts that Ranger's Ludus/GOAD ranges are deployed, and no private lab solutions or
board-specific objectives are disclosed.

## Ludus: reproducible range provisioning

Ludus (by Bad Sector Labs) is a self-hosted platform for building reproducible cyber
ranges on a hypervisor. Its architecture:

- **Virtualization:** Ludus provisions virtual machines on Proxmox VE from versioned
  templates, so a range is rebuilt identically from definition rather than by hand.
- **Definition as data:** a range is described in a configuration consumed by Ansible
  roles, which makes environments reproducible and diffable.
- **Network isolation:** ranges run on isolated virtual networks with controlled egress,
  so adversary simulation stays inside owned infrastructure.
- **Lifecycle:** deploy, snapshot, use, and tear down on demand, with the underlying host
  persisting while individual ranges come and go.

Infrastructure requirements are substantial: a hypervisor host with enough RAM and CPU
to run a multi-VM Windows and Active Directory environment concurrently per candidate,
which is the dominant cost and the reason the capability is staged rather than always-on.

## GOAD: a vulnerable Active Directory lab

GOAD (Game of Active Directory, by Orange Cyberdefense) is an intentionally vulnerable,
multi-domain Active Directory environment for practicing and detecting identity attacks.
Its topology spans multiple domains and a forest trust (for example sevenkingdoms.local
with north and essos domains), each with member servers and workstations, seeded with
realistic misconfigurations.

GOAD's value for Ranger is defensive research: it is a controlled place to study the
attack paths covered in the Active Directory Security Engineering publications
(Kerberos abuse, delegation, ACL and Group Policy weaknesses) and to validate the
telemetry and detections that catch them, mapped to MITRE ATT&CK.

## How Ranger intends to use them

The intended model keeps the shared blue-board surface separate from the virtualized
offensive ranges: Ludus provisions isolated GOAD-style environments for the advanced
boards on demand, with concurrency caps and idle teardown to control cost, while the
defensive boards continue on their per-candidate datasets. Provisioning is triggered only
by an authorized, explicit lab start, never eagerly.

## Credits

Ludus is a project of Bad Sector Labs; GOAD is a project of Orange Cyberdefense. Both are
linked as references and remain the property of their authors. Qwalora documents their
architecture and its intended use; it does not claim authorship of either.

""",
    },
    # ---- Offensive, Defensive, Red, Blue & Purple Team Operations ----------
    {
        "pub_id": "QR-KB-030",
        "slug": "red-blue-purple-team-operations",
        "title": "Red Team, Blue Team, and Purple Team Operations",
        "track": "knowledge-base", "collection": "Red, Blue & Purple Team Operations",
        "category": "offensive", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Red team, Blue team, Purple team, Adversary emulation, Detection",
        "board": 3, "role": "detection-engineer",
        "source_attribution": PUBLISHER,
        "related": "QR-KB-011,QR-RES-002",
        "refs": [
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
            {"label": "MITRE Engenuity: ATT&CK Evaluations", "url": "https://attackevals.mitre-engenuity.org/"},
            {"label": "NIST SP 800-115: Technical Guide to Information Security Testing",
             "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
        ],
        "verification": _mv(),
        "summary": "What offensive and defensive security actually mean, and how red, blue, and purple "
        "team operations differ in scope, method, and authorization. It separates penetration testing, "
        "vulnerability assessment, red teaming, and adversary emulation; describes the blue-team "
        "detection and response workflow; sets out the purple-team loop that validates detections against "
        "emulated behavior; and places the practitioner roles involved, with MITRE ATT&CK mappings and the "
        "evidence each activity should produce.",
        "body": r"""## Offensive and defensive security

Offensive security tests controls by attempting to defeat them under authorization;
defensive security builds and operates the controls, telemetry, and response. They are
two halves of the same engineering discipline, and the strongest programs run them as a
loop rather than in isolation.

**Authorization is the dividing line of all offensive work.** Every technique below is
performed only within an explicit, written scope against owned or authorized systems.
Without that, it is not security work.

## Related but distinct activities

These terms are often conflated; they are not the same:

- **Vulnerability assessment:** breadth-first identification of known weaknesses, usually
  with scanning and configuration review. Output: a prioritized list of findings.
- **Penetration testing:** goal-directed exploitation within a defined scope to prove
  exploitability and impact. Output: validated findings with evidence and remediation.
- **Red teaming:** objective-driven, adversary-style assessment of people, process, and
  technology, often with stealth and a specific goal (for example reach a crown-jewel
  asset), measuring detection and response as much as prevention.
- **Adversary emulation:** red-team work that reproduces the specific tactics, techniques,
  and procedures of a named threat actor, mapped to MITRE ATT&CK, to test coverage against
  a realistic opponent.

## Blue team operations

The blue team owns telemetry, detection, investigation, and response. The workflow:
instrument the environment to produce the right telemetry; engineer detections for
specific behaviors; triage and investigate alerts into incidents; respond to contain and
eradicate; and feed what was learned back into instrumentation and detection. Evidence
matters throughout: an investigation is only as good as the observations it preserved and
can reproduce.

## Purple team engineering

Purple teaming is the shared loop, not a third standing team. An offensive operator
executes a specific, ATT&CK-mapped behavior (for example an atomic test for a technique)
in a controlled environment; the defensive side confirms whether the behavior produced
the expected telemetry and whether a detection fired; the two sides tune the detection and
re-run. The output is a measured improvement in coverage with evidence: the behavior, the
telemetry it generated, the detection result before and after, and the delta.

A concrete loop:

1. Select a technique and an emulation of it (a safe, repeatable test).
2. Execute it in a controlled range with full telemetry capture.
3. Check the telemetry for the expected artifacts; check whether the detection fired.
4. Record PASS/FAIL with the observations preserved.
5. Tune the detection, then re-run to confirm the improvement.

## The roles involved

The same people play across these activities: security engineers build and harden;
detection engineers turn behaviors into reliable, low-false-positive detections;
incident responders investigate and contain; offensive operators emulate adversaries
under authorization. These are roles, not separate Ranger training tracks; a candidate
develops them across the boards.

## Evidence and verification

Every activity should produce evidence a reviewer can inspect: scope and authorization,
the exact actions taken, the telemetry and detection results, and a reproducible method.
Qwalora's research publications apply the same discipline to detection validation, with
signed, run-bound evidence.

""",
    },
]

assert len({p["slug"] for p in PUBLICATIONS}) == len(PUBLICATIONS), "duplicate slug in KB publications"
assert len({p["pub_id"] for p in PUBLICATIONS}) == len(PUBLICATIONS), "duplicate pub_id in KB publications"
