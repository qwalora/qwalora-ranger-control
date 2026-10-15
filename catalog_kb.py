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
        "track": "cohort-docs", "collection": "Ranger Cohort & Qualification Documentation",
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
    # ---- Ranger Cohort & Qualification Documentation (remaining) -----------
    {
        "pub_id": "QR-DOC-003",
        "slug": "board-progression-and-qualification-standards",
        "title": "Board Progression and Qualification Standards",
        "track": "cohort-docs", "collection": "Ranger Cohort & Qualification Documentation",
        "category": "frameworks", "rtype": "technical-documentation", "level": "foundational",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Boards, Qualification, Clearance, Progression",
        "source_attribution": PUBLISHER, "related": "QR-DOC-001,QR-DOC-004",
        "refs": [
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
            {"label": "NIST SP 800-181r1: Workforce Framework for Cybersecurity",
             "url": "https://csrc.nist.gov/pubs/sp/800/181/r1/final"},
        ],
        "verification": _mv(),
        "summary": "What each Ranger board measures and how a candidate clears it. This reference "
        "describes the discipline, role, and clearance criteria of the six boards, the two-channel grading "
        "model, the cohort time window, and the outcomes (cleared, graduated, withdrawn, washed out). It "
        "states standards, not solutions: no qualification test content, answer key, or grading threshold "
        "that would compromise assessment integrity is disclosed.",
        "body": r"""## How progression works

A candidate advances by clearing boards in sequence, not by elapsed time. Each board
has a discipline, a role, and a clearance that is earned on two independent channels.
A cohort runs for a fixed window; a candidate who does not clear within it is washed
out, and one who clears all six graduates with a signed certificate.

## The six boards

- **Board 1, Sentinel - security operations.** Triage security signals, separate true
  from false positives, and escalate with a defensible rationale.
- **Board 2, Tracker - threat hunting.** Form and test hypotheses against telemetry to
  find activity that no alert fired on.
- **Board 3, Warden - detection engineering.** Turn adversary behavior into reliable,
  low-false-positive detections and justify them.
- **Board 4, Reclaimer - incident response.** Reconstruct an incident from evidence,
  establish a timeline, and recommend containment and eradication.
- **Board 5, Raider - offensive operations.** Conduct authorized adversary emulation
  against an isolated environment and document findings.
- **Board 6, Vanguard - capstone.** Integrate the prior disciplines on a single
  end-to-end engagement.

## Two-channel grading

Every board is graded on an objective channel and a subjective channel. The objective
channel re-measures the candidate's technical outcome in a reproducible, answer-free
way, so there is no stored answer to leak or memorize. The subjective channel is a
human review of the candidate's written reasoning and work product. A board clears
only when both are satisfied; a strong write-up does not compensate for a failed
objective result, and vice versa.

## Outcomes

A candidate is active while progressing, graduated on clearing Board 6, withdrawn if
they leave, and washed out if the cohort window closes before they clear. Each
clearance and the final certificate are Ed25519-signed and independently verifiable.

## What this does not contain

This document states the qualification standard. It does not contain the confidential
qualification tests, the grading logic or thresholds, candidate data, or any
unpublished solution. Those remain internal to preserve the integrity of the
assessment.
""",
    },
    {
        "pub_id": "QR-DOC-004",
        "slug": "technical-deliverables-and-signed-evidence",
        "title": "Technical Deliverables and Signed Evidence",
        "track": "cohort-docs", "collection": "Ranger Cohort & Qualification Documentation",
        "category": "frameworks", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Deliverables, Evidence, Ed25519, Verifiable credentials",
        "source_attribution": PUBLISHER, "related": "QR-DOC-003,QR-RES-002",
        "refs": [
            {"label": "RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)",
             "url": "https://www.rfc-editor.org/rfc/rfc8032"},
            {"label": "NIST SP 800-61r3: Incident Response Recommendations",
             "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final"},
        ],
        "verification": _mv(),
        "summary": "What a Ranger candidate produces and how it is turned into tamper-evident, verifiable "
        "proof. This reference describes the technical deliverables each board expects, the answer-free "
        "objective grading model (the program re-measures rather than compares to a stored key), and the "
        "Ed25519 signing that makes every clearance and the final certificate independently verifiable in "
        "the browser against a published public key.",
        "body": r"""## Deliverables are work product

A Ranger candidate produces the artifacts a working practitioner produces: triage
decisions with rationale, hunt hypotheses and findings, detection logic with its
justification, reconstructed incident timelines, and operational narratives. The
deliverable is assessed to the standard a practitioner is held to, not graded against
a memorizable key.

## Answer-free objective grading

The objective channel does not compare a submission to a stored answer. Instead the
program re-measures the candidate's result: it reconstructs the technical outcome from
the candidate's own work and checks whether it meets the requirement. Because there is
no answer key in the system, there is nothing to leak, and two candidates working
different valid approaches are both assessable on the property that matters rather than
on matching a reference solution.

## Signed, verifiable evidence

When a board clears, Ranger mints a clearance and signs it with Ed25519; at graduation
it mints a certificate with a public, human-typeable credential id. Anyone can verify a
credential in the browser against the published public key: the signature proves the
claim, so a rank cannot be self-reported or forged. Certificates carry an issue date
and a validity window derived from the signed claim, so expiry is always correct
without a background job.

## Why this matters

The same evidence discipline underlies Qwalora's security research: observations are
signed and bound to the run that produced them, and anyone can re-verify them. A
Ranger credential is therefore not a participation marker; it is a cryptographically
verifiable statement that a specific standard was met.
""",
    },
    # ---- Core Technical Prerequisites (4 detailed references) --------------
    {
        "pub_id": "QR-KB-001",
        "slug": "linux-administration-and-troubleshooting",
        "title": "Linux Administration and Troubleshooting",
        "track": "knowledge-base", "collection": "Core Technical Prerequisites",
        "category": "linux-sysadmin", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Linux, systemd, Permissions, Troubleshooting",
        "source_attribution": PUBLISHER, "related": "QR-DOC-002,QR-KB-002",
        "refs": [
            {"label": "Linux man-pages project", "url": "https://man7.org/linux/man-pages/"},
            {"label": "The Linux Command Line (William Shotts)", "url": "https://linuxcommand.org/tlcl.php"},
        ],
        "verification": _mv(),
        "summary": "The Linux administration competency Ranger assumes: the filesystem, process and "
        "permission models, systemd service management, log analysis with journald, storage, and "
        "systematic troubleshooting, with the diagnostic commands a practitioner reaches for and a "
        "self-assessment. A competency reference for an engineer who already works in Linux, not a "
        "beginner course.",
        "body": r"""## Required competency

Administer a headless Linux host end to end: manage identities and permissions, control
services, read logs, inspect the running system, and resolve failures from first
principles. Ranger assumes this on day one.

## Architecture to understand

The filesystem hierarchy and mount model; the process model (PID tree, signals, exit
codes); the discretionary permission model (user/group/other, setuid/setgid/sticky,
and the difference between file and directory permissions); systemd units, targets, and
dependencies; journald and the traditional log files; and package and storage
management.

## Representative diagnostics

```
systemctl status <svc>; journalctl -u <svc> -e
ss -tlnp                      # listening sockets and owning processes
ps auxf; pstree -p            # process tree
lsof -p <pid>; lsof -i :443   # open files and sockets
find / -perm -4000 -type f 2>/dev/null   # setuid binaries
stat <file>; namei -l <path>  # resolve permissions along a path
dmesg -T | tail; df -h; du -xsh *; lsblk
```

## A troubleshooting method

Reproduce the failure; locate the layer (application, service manager, kernel, network,
storage); read the evidence (logs, exit codes, system state) before changing anything;
form one hypothesis and test it; and confirm the fix restored the expected behavior.
The discipline matters more than any single command.

## Self-assessment

Given a service that fails to start on boot, can you determine the cause from unit state
and logs alone, explain it precisely, and fix it, in minutes? Can you find which process
holds a port, which file a process cannot write, and why a permission is denied along a
path? If any of these is unfamiliar, close the gap before applying.
""",
    },
    {
        "pub_id": "QR-KB-002",
        "slug": "networking-dns-tcpip-and-network-analysis",
        "title": "Networking, DNS, TCP/IP and Network Analysis",
        "track": "knowledge-base", "collection": "Core Technical Prerequisites",
        "category": "networking", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "TCP/IP, DNS, Routing, Packet analysis",
        "source_attribution": PUBLISHER, "related": "QR-KB-001,QR-KB-014",
        "refs": [
            {"label": "RFC 9293: Transmission Control Protocol", "url": "https://www.rfc-editor.org/rfc/rfc9293"},
            {"label": "Wireshark User's Guide", "url": "https://www.wireshark.org/docs/wsug_html_chunked/"},
        ],
        "verification": _mv(),
        "summary": "The networking competency Ranger assumes: the TCP/IP layers, addressing and "
        "subnetting, routing, DNS resolution, TLS handshake basics, and reading traffic at the packet "
        "level. It gives the architecture, representative commands and display filters, and a "
        "self-assessment built around narrating a capture. Network fluency is what makes detection and "
        "intrusion analysis possible.",
        "body": r"""## Required competency

Reason about network traffic at the protocol and packet level and diagnose connectivity
and name resolution without guessing. Much of security operations is reading what
actually crossed the wire.

## Architecture to understand

The TCP/IP layers and how a request flows through them; IPv4/IPv6 addressing, subnetting
and CIDR; the routing decision and the default gateway; the DNS resolution path
(recursive and authoritative, record types, SRV records used by Active Directory); the
TCP three-way handshake, flags, and teardown; and the TLS handshake at a high level.

## Representative commands and filters

```
ip addr; ip route; ip neigh
ss -tanp                          # connections and owners
dig +trace example.com; dig _ldap._tcp.dc._msdcs.<domain> SRV
tcpdump -ni any 'tcp port 443 and tcp[tcpflags] & tcp-syn != 0'
```

Wireshark display filters: `tcp.flags.syn==1 && tcp.flags.ack==0` (connection starts),
`dns`, `tls.handshake.type==1` (client hello), `ip.addr==10.0.0.5 && tcp.port==445`.

## Network analysis

Given a capture, identify the conversations, narrate a TCP handshake and a DNS lookup,
spot a reset or retransmission storm, and locate where a failure or anomaly occurred.
This is the same skill that underpins intrusion analysis on the blue boards.

## Self-assessment

Can you subnet by hand, predict the routing decision for a destination, trace a DNS
resolution including the SRV lookups a domain-joined host performs, and read a short
pcap to explain exactly what happened and where it broke?
""",
    },
    {
        "pub_id": "QR-KB-003",
        "slug": "bash-python-git-and-engineering-automation",
        "title": "Bash, Python, Git and Engineering Automation",
        "track": "knowledge-base", "collection": "Core Technical Prerequisites",
        "category": "engineering", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Bash, Python, Git, Automation, CI",
        "source_attribution": PUBLISHER, "related": "QR-KB-001,QR-RES-001",
        "refs": [
            {"label": "Pro Git (git-scm.com)", "url": "https://git-scm.com/book/en/v2"},
            {"label": "Python 3 documentation", "url": "https://docs.python.org/3/"},
            {"label": "GitHub Actions documentation", "url": "https://docs.github.com/en/actions"},
        ],
        "verification": _mv(),
        "summary": "The automation competency Ranger assumes: robust Bash, practical Python, real Git, "
        "and the habit of turning manual work into reproducible, version-controlled automation. It covers "
        "the shell execution model, Python for files, processes and JSON, Git branching and history, and "
        "where CI fits, with representative patterns and a self-assessment. Ranger's own grading runs as "
        "automated, answer-free checks, so this fluency is load-bearing.",
        "body": r"""## Required competency

Automate work reliably and manage it under version control. A Ranger candidate writes a
robust Bash script, a small Python program, and a clean Git history as a matter of
course, because the program's objective grading runs as automated checks and the work
product is tracked in repositories.

## Bash

Understand the execution and quoting model, exit codes, and pipelines. Write defensively:

```
set -euo pipefail
trap 'echo "failed at line $LINENO" >&2' ERR
while IFS= read -r line; do process "$line"; done < input.txt
```

Use `grep`, `sed`, `awk`, and `jq` to transform text and JSON rather than parsing by hand.

## Python

Use the standard library with intent: `pathlib` and `open` for files, `subprocess` for
external commands (prefer argument lists over shell strings), `json` for structured data,
`argparse` for interfaces, and `pytest` for tests. Write small, testable functions.

## Git

Branch, rebase, and read history fluently: `git log --oneline --graph`, `git rebase -i`,
`git bisect` to isolate a regression, and a clean, reviewable commit series. Treat
history as communication.

## Automation and CI

Know where continuous integration fits: a push triggers checks that build, test, and
report, producing a reproducible result rather than a local, unrepeatable one. Ranger's
answer-free objective grading is exactly this pattern.

## Self-assessment

Can you turn a manual, multi-step task into a reproducible script with error handling,
cover it with a test, and track it in Git with a history a reviewer can follow?
""",
    },
    {
        "pub_id": "QR-KB-004",
        "slug": "windows-administration-and-core-active-directory",
        "title": "Windows Administration and Core Active Directory",
        "track": "knowledge-base", "collection": "Core Technical Prerequisites",
        "category": "offensive", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Windows, PowerShell, Active Directory, Entra ID",
        "source_attribution": PUBLISHER, "related": "QR-KB-010,QR-KB-014",
        "refs": [
            {"label": "Microsoft Learn: PowerShell documentation",
             "url": "https://learn.microsoft.com/en-us/powershell/"},
            {"label": "Microsoft Learn: Windows Server documentation",
             "url": "https://learn.microsoft.com/en-us/windows-server/"},
        ],
        "verification": _mv(),
        "summary": "The Windows competency Ranger assumes before the advanced boards: operating Windows "
        "from PowerShell, the Windows security model (SIDs, tokens, privileges), the event log, and the "
        "fundamentals of Active Directory Domain Services, with the distinction between AD DS, Microsoft "
        "Entra ID, and Entra Domain Services made explicit. Representative commands and a self-assessment "
        "are included.",
        "body": r"""## Required competency

Operate Windows from PowerShell and understand the identity and security model the
advanced boards build on. A candidate should be comfortable querying the system and
reading the Security log before encountering Active Directory attack paths.

## Windows administration

PowerShell and the object pipeline; services and scheduled tasks; the Windows security
model (security identifiers, access tokens, privileges, and the difference between a
privilege and a permission); and the event log.

```
Get-Service | Where-Object Status -eq 'Running'
whoami /all                                   # SIDs, groups, privileges
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 20
Get-LocalUser; Get-LocalGroupMember Administrators
```

## Core Active Directory Domain Services

Understand domains, forests, organizational units, domain controllers, and Group Policy
at a conceptual level (the architecture is developed in the Active Directory Security
Engineering collection). On a domain-joined host:

```
Get-ADDomain; Get-ADUser -Filter * -Properties LastLogonDate
Get-ADGroup -Filter * | Select-Object Name
```

## A necessary distinction

**AD DS** is the on-premises directory using Kerberos and LDAP. **Microsoft Entra ID**
(formerly Azure AD) is a cloud identity service using OAuth 2.0, OpenID Connect, and SAML;
it is not a domain controller in the cloud. **Microsoft Entra Domain Services** is a
managed domain in Azure that provides AD DS-compatible services. They are related but
distinct; Ranger's advanced boards operate against AD DS.

## Self-assessment

Can you query the Security log for sign-in events and explain what a logon type indicates,
enumerate local privileges from your token, and describe what a domain controller is
responsible for and how AD DS differs from Entra ID?
""",
    },
    # ---- Active Directory Security Engineering (remaining) ------------------
    {
        "pub_id": "QR-KB-012",
        "slug": "ldap-queries-and-directory-enumeration",
        "title": "LDAP Queries and Directory Enumeration",
        "track": "knowledge-base", "collection": "Active Directory Security Engineering",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "LDAP, Enumeration, Directory, Detection",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER, "related": "QR-KB-010,QR-KB-013",
        "refs": [
            {"label": "Microsoft Learn: Lightweight Directory Access Protocol",
             "url": "https://learn.microsoft.com/en-us/windows/win32/ad/about-the-lightweight-directory-access-protocol"},
            {"label": "MITRE ATT&CK: Account Discovery (T1087)", "url": "https://attack.mitre.org/techniques/T1087/"},
            {"label": "MITRE ATT&CK: Domain Trust Discovery (T1482)", "url": "https://attack.mitre.org/techniques/T1482/"},
        ],
        "verification": _mv(),
        "summary": "How LDAP is used to query Active Directory and how directory enumeration looks from "
        "both sides. It covers distinguished names, search bases and scopes, LDAP filter syntax, and the "
        "objects an operator or defender enumerates (users, groups, computers, SPNs, GPOs, trusts), with "
        "representative queries, the security implications, the detection signals, and the controls that "
        "limit abusive enumeration.",
        "body": r"""## LDAP in Active Directory

Active Directory exposes its database over the Lightweight Directory Access Protocol.
Every object has a distinguished name (DN), for example
`CN=jdoe,OU=Staff,DC=corp,DC=example,DC=com`, and queries specify a search base, a scope
(base, one-level, or subtree), and a filter.

## Filter syntax

LDAP filters are prefix-notation and composable:

```
(&(objectClass=user)(objectCategory=person))
(&(objectClass=user)(servicePrincipalName=*))        # accounts with SPNs
(userAccountControl:1.2.840.113556.1.4.803:=524288)  # accounts trusted for delegation
(&(objectClass=group)(adminCount=1))                  # protected / privileged groups
```

## Representative enumeration

```
# Linux
ldapsearch -x -H ldap://dc.corp.example.com -b "DC=corp,DC=example,DC=com" \
  "(&(objectClass=user)(servicePrincipalName=*))" sAMAccountName servicePrincipalName
# Windows, built-in
dsquery user -limit 0
Get-ADComputer -Filter * -Properties OperatingSystem | Select Name,OperatingSystem
Get-ADObject -LDAPFilter "(objectClass=trustedDomain)"
```

These are read-only directory reads illustrative of structure; they are not labeled as
tested here.

## Security implications

Directory enumeration is the reconnaissance that precedes most Active Directory attacks:
mapping privileged groups, service accounts with SPNs (for Kerberoasting targeting),
delegation settings, and trusts (for cross-domain movement). The directory is designed
to be queryable, so the defensive question is not whether enumeration is possible but
whether abusive enumeration is visible. Maps to MITRE ATT&CK T1087 and T1482.

## Detection and defensive controls

Directory access is auditable (event 4662 for operations on directory objects, with SACLs
on sensitive objects). Watch for broad or scripted enumeration, LDAP queries for
delegation and SPN attributes from unusual hosts, and anonymous or unauthenticated binds.
Disable anonymous bind, scope SACL auditing to sensitive objects, and monitor for the
specific high-signal filters above.
""",
    },
    {
        "pub_id": "QR-KB-013",
        "slug": "group-policy-acls-privileged-identities-attack-paths",
        "title": "Group Policy, ACLs, Privileged Identities and Attack Paths",
        "track": "knowledge-base", "collection": "Active Directory Security Engineering",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Group Policy, ACLs, Privileged access, Attack paths",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER, "related": "QR-KB-012,QR-KB-014",
        "refs": [
            {"label": "Microsoft Learn: Group Policy overview",
             "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh831791(v=ws.11)"},
            {"label": "Microsoft: Securing Privileged Access / tier model",
             "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model"},
            {"label": "MITRE ATT&CK: Domain Policy Modification (T1484)", "url": "https://attack.mitre.org/techniques/T1484/"},
        ],
        "verification": _mv(),
        "summary": "How Group Policy, access control lists, and privileged identities create (or close) "
        "attack paths in Active Directory. It explains the GPO architecture and scoping, the ACL/ACE model "
        "and the rights that matter for escalation, the protected privileged groups and the tier model, "
        "and how attack paths are reasoned about and cut, with the relevant detection events and defensive "
        "controls.",
        "body": r"""## Group Policy

Group Policy Objects (GPOs) deliver configuration and security settings to users and
computers. A GPO is linked to a site, domain, or organizational unit, and its settings
apply by scope and precedence. Because GPOs can configure powerful things (scripts,
scheduled tasks, local group membership, user rights), control over a GPO linked to
sensitive objects is itself a privileged position. Unauthorized GPO modification maps to
MITRE ATT&CK T1484.001.

## The ACL/ACE model

Every directory object has a security descriptor with a discretionary access control
list (DACL) of access control entries (ACEs). Certain rights are escalation-relevant:
`GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, and
`AddMember`. An overbroad or misconfigured ACE on a privileged object or group lets a
lower-privileged principal take control of a higher-privileged one.

## Privileged identities and the tier model

Protected groups (Domain Admins, Enterprise Admins, and others marked by `adminCount`)
are the directory's crown jewels. The tier model limits where privileged credentials are
exposed: Tier 0 (identity infrastructure such as domain controllers) credentials must
never authenticate to lower tiers, because a single exposure on a workstation can lead to
domain compromise.

## Attack paths

An attack path is a chain of such relationships, for example: control of a workstation
leads to a cached credential, which has `WriteDacl` on a group, whose members can reset a
service account, which is a member of a privileged group. Defenders reason about these
paths as a graph and cut the shortest ones first. (Graph analysis of ACLs and group
membership is how tools such as BloodHound model this; the concept, not any one tool, is
the point.)

## Detection and defensive controls

Audit directory object changes (event 5136), GPO changes (event 5137/5141 and 4670 for
permission changes), and privileged group membership changes (4728/4732/4756). Minimize
and monitor protected-group membership, enforce the tier model, remove unnecessary ACEs,
and treat control of a Tier 0 GPO or object as equivalent to domain compromise.
""",
    },
    {
        "pub_id": "QR-KB-014",
        "slug": "windows-event-telemetry-investigation-detection",
        "title": "Windows Event Telemetry, Investigation and Detection Engineering",
        "track": "knowledge-base", "collection": "Active Directory Security Engineering",
        "category": "ir-forensics", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Windows events, Sysmon, Detection, Investigation",
        "board": 3, "role": "detection-engineer",
        "source_attribution": PUBLISHER, "related": "QR-KB-011,QR-KB-013",
        "refs": [
            {"label": "Microsoft Learn: Advanced security audit policy settings",
             "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings"},
            {"label": "Sysmon (Sysinternals)",
             "url": "https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(),
        "summary": "The Windows telemetry a defender relies on, how to investigate with it, and how to "
        "engineer detections on it. It covers the Security log and Sysmon, the high-value event IDs for "
        "authentication, process creation, and lateral movement, logon types and their meaning, and a "
        "detection-engineering method that maps behaviors to ATT&CK and expresses them as portable rules.",
        "body": r"""## The telemetry

Windows emits rich security telemetry through the Security event log and, with it
installed, Sysmon. The defender's job is to ensure the right events are generated, collect
them centrally, and build reliable detections on them.

## High-value event IDs

- **Authentication:** 4624 (logon), 4625 (failed logon), 4648 (explicit credentials),
  4672 (privileged logon), and the Kerberos events 4768/4769/4771.
- **Process and lateral movement:** 4688 (process creation, with command line when
  enabled), 7045 (service installed), 5140/5145 (network share access), 4697 (service
  installed via SCM).
- **Sysmon:** Event 1 (process creation with hashes and parent), 3 (network connection),
  7 (image load), 11 (file create), 8 (remote thread), 22 (DNS query).

## Logon types

Event 4624 carries a logon type that changes its meaning: 2 (interactive), 3 (network,
for example SMB), 4 (batch), 5 (service), 9 (new credentials, as in runas /netonly), and
10 (remote interactive, RDP). Type 3 with explicit credentials across many hosts, or type
9, are classic lateral-movement signals.

## Investigation

Reconstruct activity by correlating these events across hosts and time: a failed-then-
successful logon sequence, a privileged logon followed by service installation, or an
unusual parent/child process chain. Preserve the observations (host, timestamp, event
data) so the reconstruction is reproducible, the same discipline the incident-response
board grades.

## Detection engineering

Turn a specific behavior into a detection: define the behavior and its ATT&CK technique,
identify the telemetry that proves it, express the logic in a portable form (for example
a Sigma rule over the relevant event fields), and tune it against benign baselines to
control false positives. A detection is only finished when its false-positive and
false-negative behavior is understood, which is why validation (see the purple-team
publication) is part of the work, not an afterthought.
""",
    },
    # ---- Ludus & GOAD Lab Architecture (remaining) -------------------------
    {
        "pub_id": "QR-KB-021",
        "slug": "goad-active-directory-adversary-emulation",
        "title": "GOAD: Active Directory Adversary Emulation",
        "track": "knowledge-base", "collection": "Ludus & GOAD Lab Architecture",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "GOAD, Adversary emulation, Active Directory, Defense",
        "board": 5, "role": "red-teamer",
        "source_attribution": "Qwalora LLC. GOAD by Orange Cyberdefense.",
        "related": "QR-KB-020,QR-KB-011",
        "refs": [
            {"label": "GOAD (Game of Active Directory), Orange Cyberdefense",
             "url": "https://github.com/Orange-Cyberdefense/GOAD"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(
            "Reviewed documentation of the GOAD lab and its use for defensive research. GOAD is a "
            "third-party project by Orange Cyberdefense. Ranger's own GOAD environments are planned, not "
            "operational; nothing here claims they are deployed, and no private lab solutions or board "
            "objectives are disclosed."),
        "summary": "A closer look at GOAD, the intentionally vulnerable multi-domain Active Directory lab, "
        "and its value for defensive research. It describes the identity attack surface GOAD exposes "
        "(authentication weaknesses, delegation, ACL and Group Policy misconfigurations, trust abuse), the "
        "defensive research it enables (telemetry and detection validation), and the ATT&CK techniques it "
        "exercises. GOAD is an Orange Cyberdefense project; Ranger's own GOAD environments are planned, "
        "not operational.",
        "body": r"""## Status and credit

GOAD (Game of Active Directory) is a project of Orange Cyberdefense: an intentionally
vulnerable, multi-domain Active Directory environment for learning and detecting identity
attacks. Ranger's own GOAD environments are **planned infrastructure for the advanced
boards, not a live production capability.** Nothing here asserts they are deployed, and no
private lab solution or board-specific objective is disclosed.

## Why an intentionally vulnerable lab

Real Active Directory attacks exploit misconfiguration more than software vulnerabilities,
so a realistic lab is one seeded with the misconfigurations that occur in the field. GOAD
provides a multi-domain forest with member servers and workstations and a curated set of
weaknesses, so the same attack paths that appear in production can be studied and, more
importantly for a defensive program, detected and remediated in a controlled place.

## The identity attack surface

GOAD exercises the attack surface covered in the Active Directory Security Engineering
collection: Kerberos weaknesses (Kerberoasting, AS-REP roasting, delegation abuse), ACL
and Group Policy misconfigurations that create escalation paths, credential exposure and
reuse across tiers, and trust relationships that enable cross-domain movement. Each maps
to MITRE ATT&CK techniques and, crucially, to specific telemetry.

## Defensive research applications

For Ranger the value is defensive. GOAD is where a detection engineer validates that a
given attack behavior produces the expected Windows and Sysmon telemetry, that a detection
fires on it, and that the fix removes the path, exactly the purple-team loop. It is also
where an incident responder practices reconstructing an identity attack from evidence.

## How Ranger intends to use it

Provisioned on demand through the range platform (see Ludus and GOAD Environment
Architecture) as an isolated environment per authorized lab start, with the defensive
boards continuing on their per-candidate datasets. The intent is defensive skill under
realistic conditions, not a catalog of exploits.
""",
    },
    {
        "pub_id": "QR-KB-022",
        "slug": "ranger-advanced-boards-environment-readiness",
        "title": "Ranger Advanced Boards: Environment Readiness",
        "track": "cohort-docs", "collection": "Ludus & GOAD Lab Architecture",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Readiness, Advanced boards, Active Directory, Lab",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER, "related": "QR-KB-020,QR-KB-004",
        "refs": [
            {"label": "Microsoft Learn: Active Directory Domain Services",
             "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-domain-services"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(),
        "summary": "The technical competencies a candidate is expected to hold before using Ranger's "
        "advanced Windows and Active Directory environments, and a clear statement of what is deployed "
        "versus planned. It is a readiness reference for the Raider and Vanguard boards: it names the "
        "prerequisite knowledge, points to the relevant publications, and sets expectations without "
        "disclosing board objectives.",
        "body": r"""## Deployed versus planned

The advanced boards (Raider and the Vanguard capstone) are designed to run on isolated,
virtualized Active Directory environments. Those environments are **planned
infrastructure, not a live production capability today**; the defensive boards currently
run on per-candidate datasets. This document states the readiness a candidate needs for
the advanced boards once that infrastructure is live, and it does not claim the
environments are operational or disclose board objectives.

## Readiness a candidate must hold

Before the advanced Windows and Active Directory environments, a candidate is expected to:

- Operate Windows from PowerShell and read the Security log (see Windows Administration
  and Core Active Directory).
- Understand AD DS architecture: domains, forests, OUs, domain controllers, the global
  catalog, and DNS/SRV dependence (see Active Directory Domain Services Architecture).
- Understand Kerberos and NTLM authentication and their abuse at a detection level (see
  Kerberos Authentication and Detection).
- Reason about LDAP enumeration, ACLs, Group Policy, privileged identities, and attack
  paths (see the corresponding publications).
- Correlate Windows and Sysmon telemetry into an investigation (see Windows Event
  Telemetry, Investigation and Detection Engineering).

## How the environment is used

Advanced environments are provisioned on demand through the range platform as isolated
instances per authorized lab start, with network isolation and controlled egress so
adversary emulation stays inside owned infrastructure. A candidate works authorized,
scoped objectives and produces evidence to the same standard as every other board.

## What this does not contain

This is a readiness reference. It does not contain board objectives, lab solutions, or any
unpublished content; those remain internal.
""",
    },
    # ---- Offensive, Defensive, Red, Blue & Purple Team Operations (rest) ---
    {
        "pub_id": "QR-KB-031",
        "slug": "offensive-vs-defensive-security-scope-methods-authorization",
        "title": "Offensive Security vs Defensive Security: Scope, Methods and Authorization",
        "track": "knowledge-base", "collection": "Red, Blue & Purple Team Operations",
        "category": "offensive", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Offensive, Defensive, Authorization, Scope",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER, "related": "QR-KB-030,QR-KB-032",
        "refs": [
            {"label": "NIST SP 800-115: Technical Guide to Information Security Testing",
             "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(),
        "summary": "What separates offensive from defensive security in scope, method, and above all "
        "authorization, and how the related activities (vulnerability assessment, penetration testing, red "
        "teaming, adversary emulation) differ. It sets out rules of engagement and scope as the "
        "precondition of all offensive work, the methods each discipline uses, and the evidence each must "
        "produce, so the distinctions are operational rather than semantic.",
        "body": r"""## Two halves of one discipline

Offensive security tries to defeat controls under authorization to measure how they hold;
defensive security builds, operates, and improves those controls and the telemetry and
response around them. Mature programs run them as one loop. Everything offensive below is
performed only within explicit written authorization against owned or authorized systems;
without that boundary it is not security work.

## Authorization and scope come first

Before any offensive activity: a written scope (targets, exclusions, time windows), rules
of engagement (permitted techniques, handling of discovered data, stop conditions and
contacts), and explicit authorization from an owner who can grant it. These are not
paperwork; they are what distinguishes a security assessment from an intrusion.

## The related activities, distinguished

- **Vulnerability assessment:** breadth-first identification of known weaknesses, usually
  via scanning and configuration review. Output: a prioritized findings list.
- **Penetration testing:** goal-directed exploitation within scope to prove exploitability
  and impact. Output: validated findings with evidence and remediation.
- **Red teaming:** objective-driven, adversary-style assessment of people, process, and
  technology, often stealthy, measuring detection and response as much as prevention.
- **Adversary emulation:** red teaming that reproduces a specific threat actor's TTPs
  mapped to MITRE ATT&CK, to test coverage against a realistic opponent.

They answer different questions and produce different evidence; calling a vulnerability
scan a red team misrepresents both the method and the assurance it provides.

## Defensive methods

Instrumentation, detection engineering, investigation, and response, each producing
evidence a reviewer can inspect and reproduce. The defensive side is measured on time to
detect and respond and on coverage against real techniques, not on the absence of alerts.

## Evidence

Every activity, offensive or defensive, should produce: the scope and authorization, the
exact actions taken, the observations and results, and a reproducible method. This is the
standard Ranger grades, and the standard Qwalora's research applies with signed evidence.
""",
    },
    {
        "pub_id": "QR-KB-032",
        "slug": "red-team-operations-adversary-objectives-emulation-assessment",
        "title": "Red Team Operations: Adversary Objectives, Emulation and Assessment",
        "track": "knowledge-base", "collection": "Red, Blue & Purple Team Operations",
        "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Red team, Adversary emulation, ATT&CK, Assessment",
        "board": 5, "role": "red-teamer",
        "source_attribution": PUBLISHER, "related": "QR-KB-031,QR-KB-033",
        "refs": [
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
            {"label": "MITRE Engenuity: ATT&CK Evaluations", "url": "https://attackevals.mitre-engenuity.org/"},
        ],
        "verification": _mv(),
        "summary": "How red team operations are planned and run as objective-driven adversary emulation, "
        "and how they are assessed. It covers defining objectives and threat scenarios, building an "
        "emulation plan from MITRE ATT&CK, operating with discipline (OPSEC, deconfliction, evidence "
        "capture), and measuring the engagement by detection and response rather than by whether the "
        "objective was reached. Techniques are framed for authorized assessment, not as tooling.",
        "body": r"""## What a red team measures

A red team measures how an organization detects and responds to a realistic adversary, not
merely whether a system can be broken. The engagement is defined by objectives (for
example, reach a specific crown-jewel asset or demonstrate a business-impacting action)
and by the threat it emulates.

## Building an emulation plan

Select a threat scenario and translate it into concrete behaviors using MITRE ATT&CK:
initial access, execution, persistence, privilege escalation, credential access, discovery,
lateral movement, collection, command and control, and impact. An emulation plan lists the
techniques to exercise, the expected observable artifacts, and the success and stop
criteria. Reproducing a named actor's TTPs is adversary emulation; a generic objective-
driven assessment is red teaming more broadly.

## Operating with discipline

Red team work under authorization still demands discipline: operational security so the
assessment itself does not create risk, deconfliction with the defenders' management so a
real incident is not missed, careful handling of any sensitive data encountered, and
continuous evidence capture (what was done, when, from where, and what was observed).
Stop conditions and contacts are agreed before starting.

## Assessment and reporting

The engagement is assessed on the defensive outcome: which behaviors were detected, how
quickly, how the response unfolded, and where coverage gaps lie, mapped back to ATT&CK.
The report pairs each emulated technique with whether telemetry existed, whether a
detection fired, and the recommended improvement. MITRE Engenuity's ATT&CK Evaluations
are a public example of this behavior-mapped assessment style.

## The role

Offensive operators do this work; its output feeds detection engineers and incident
responders. It is a role within a program, not a separate Ranger training track, and the
advanced boards develop it under authorized, scoped conditions.
""",
    },
    {
        "pub_id": "QR-KB-033",
        "slug": "blue-team-operations-telemetry-detection-investigation-response",
        "title": "Blue Team Operations: Telemetry, Detection, Investigation and Response",
        "track": "knowledge-base", "collection": "Red, Blue & Purple Team Operations",
        "category": "secops-siem", "rtype": "technical-documentation", "level": "intermediate",
        "pub_type": "technical-methodology", "version": "1.0.0", "maturity": "technical-review",
        "publisher": PUBLISHER, "topic": "Blue team, Telemetry, Detection, Incident response",
        "board": 1, "role": "soc-analyst",
        "source_attribution": PUBLISHER, "related": "QR-KB-032,QR-KB-014",
        "refs": [
            {"label": "NIST SP 800-61r3: Incident Response Recommendations",
             "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final"},
            {"label": "MITRE ATT&CK (Enterprise)", "url": "https://attack.mitre.org/"},
        ],
        "verification": _mv(),
        "summary": "How blue team operations turn telemetry into detection, investigation, and response. "
        "It covers the telemetry sources that matter, the detection-engineering workflow, alert triage and "
        "escalation, and the incident-response lifecycle aligned to NIST SP 800-61, with the evidence each "
        "stage must preserve. It connects directly to the defensive Ranger boards (SOC analysis through "
        "incident response).",
        "body": r"""## The blue team's job

The blue team owns the full defensive loop: generate the right telemetry, detect specific
adversary behaviors, investigate alerts into incidents, respond to contain and eradicate,
and feed what was learned back into instrumentation and detection.

## Telemetry

Detection is only as good as the data under it. Core sources: endpoint process and
authentication events (Windows Security log, Sysmon, Linux auditd), network metadata and
captures (Zeek, firewall and proxy logs), identity events (domain controller logs,
Kerberos events), and application and cloud audit logs. The first engineering task is
ensuring the needed events are produced and centralized.

## Detection engineering

Turn a behavior into a reliable detection: define the behavior and its ATT&CK technique,
identify the proving telemetry, express the logic portably (for example Sigma over
normalized fields), and tune against benign baselines to control false positives. A
detection is finished only when its false-positive and false-negative behavior is
understood.

## Triage and investigation

An analyst separates true from false positives with a defensible rationale, then
investigates true positives by correlating events across hosts and time into a coherent
account. Preserve the observations so the reconstruction is reproducible, the standard the
SOC and incident-response boards grade.

## Incident response

Follow a lifecycle aligned to NIST SP 800-61: preparation, detection and analysis,
containment, eradication and recovery, and post-incident activity. Each phase produces
evidence: the detection that fired, the scope established, the actions taken and their
effect, and the lessons that change instrumentation and detection for next time.

## The roles

SOC analysts, detection engineers, and incident responders are the blue-team roles; they
consume what offensive operators surface and close the loop with them in purple-team work.
They are roles within a program, developed across the defensive boards.
""",
    },
]

assert len({p["slug"] for p in PUBLICATIONS}) == len(PUBLICATIONS), "duplicate slug in KB publications"
assert len({p["pub_id"] for p in PUBLICATIONS}) == len(PUBLICATIONS), "duplicate pub_id in KB publications"
