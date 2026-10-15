"""Qwalora Ranger resource library catalog.

The canonical editorial inventory for the public resource library. Each entry
carries full metadata (category, standardized type, technical level, publisher,
a 70 to 120 word original editorial description, secondary tags, board/role
associations where technically justified, source attribution and review date).

These records are upserted into the Resource model by stable `slug`
(insert-if-missing, so admin curation is never overwritten and no duplicates are
created). External entries are published; original Qwalora publications are kept
as drafts until technical review.

Descriptions are original editorial summaries written for Ranger. They are not
copied from the publishers. No reading durations, difficulty ratings,
certifications, endorsements or learning outcomes are invented.
"""

CATEGORY_LABELS = {
    "linux-sysadmin": "Linux & System Administration",
    "networking": "Networking & Infrastructure",
    "secops-siem": "Security Operations & SIEM",
    "threat-intel": "Threat Intelligence & Vulnerability Research",
    "ir-forensics": "Incident Response & Digital Forensics",
    "offensive": "Offensive Security & Adversary Emulation",
    "engineering": "Engineering, Automation & Secure Development",
    "frameworks": "Security Frameworks & Research Standards",
}
# Short labels for compact UI (facet chips, card meta).
CATEGORY_SHORT = {
    "linux-sysadmin": "Linux & Sysadmin",
    "networking": "Networking",
    "secops-siem": "SecOps & SIEM",
    "threat-intel": "Threat Intel & Vuln",
    "ir-forensics": "IR & Forensics",
    "offensive": "Offensive Security",
    "engineering": "Engineering & Automation",
    "frameworks": "Frameworks & Standards",
}
TYPE_LABELS = {
    "technical-documentation": "Technical Documentation",
    "research-publication": "Research Publication",
    "technical-standard": "Technical Standard",
    "reference-guide": "Reference Guide",
    "technical-book": "Technical Book",
    "security-advisory": "Security Advisory",
    "threat-intelligence": "Threat Intelligence",
    "open-source-project": "Open-Source Project",
    "external-course": "External Course",
    "practical-exercise": "Practical Exercise",
}
LEVEL_LABELS = {
    "foundational": "Foundational", "intermediate": "Intermediate",
    "advanced": "Advanced", "research": "Research",
}

# Research-publication maturity (how far the research itself has progressed).
MATURITY_LABELS = {
    "draft": "Draft", "implemented": "Implemented", "executed": "Executed",
    "independently-checked": "Independently Checked", "technical-review": "Technical Review",
    "approved": "Approved for Publication", "published": "Published", "superseded": "Superseded",
}
# Evidence maturity of a publication's claim.
PUB_TYPE_LABELS = {
    "verified-research": "Verified Research",
    "evaluated-artifact": "Evaluated Engineering Artifact",
    "technical-methodology": "Technical Methodology",
    "research-in-progress": "Research in Progress",
}
# Top-level catalog collections (navigation).
TRACK_LABELS = {
    "research": "Security Research & Engineering",
    "cohort-docs": "Ranger Cohort & Board Documentation",
    "knowledge-base": "Cybersecurity Knowledge Base",
}
TRACK_SHORT = {
    "research": "Research & Engineering",
    "cohort-docs": "Cohort & Board Docs",
    "knowledge-base": "Knowledge Base",
}

REVIEWED = "2026-10-14"  # technical review date for the verified external catalog

# --- 40 external references, 8 categories, five or more per category ---------
CATALOG = [
    # ---- A. Linux & System Administration -----------------------------------
    {"slug": "lf-intro-to-linux", "title": "Introduction to Linux (LFS101)",
     "category": "linux-sysadmin", "rtype": "external-course", "level": "foundational",
     "publisher": "The Linux Foundation", "topic": "Linux, Command line, Filesystem",
     "url": "https://training.linuxfoundation.org/training/introduction-to-linux/",
     "source_attribution": "The Linux Foundation",
     "summary": "A structured, self-paced introduction to the Linux operating system covering the "
     "filesystem hierarchy, the shell, file operations, users and permissions, processes and basic "
     "administration across major distribution families. It matters because every Ranger lab host, "
     "SIEM node and analysis workstation runs on Linux, and fluency at the command line is assumed "
     "rather than taught inside the program. It benefits applicants who need to close gaps before "
     "admission and operators who want a canonical reference for core concepts. It maps directly to "
     "Ranger's expectation that candidates operate a Linux system independently from day one."},
    {"slug": "tlcl-linux-command-line", "title": "The Linux Command Line",
     "category": "linux-sysadmin", "rtype": "technical-book", "level": "foundational",
     "publisher": "William Shotts (LinuxCommand.org)", "topic": "Shell, Bash, Command line",
     "url": "https://linuxcommand.org/tlcl.php",
     "source_attribution": "William Shotts, LinuxCommand.org",
     "summary": "A complete, freely available book that teaches the Linux command line from first "
     "principles: shell navigation, file manipulation, redirection and pipelines, permissions, "
     "process control, package handling and shell scripting. It matters because Ranger graders and "
     "lab tooling are driven from the terminal, and comfort with pipelines and scripting is a daily "
     "requirement rather than an occasional convenience. It benefits candidates building durable "
     "shell fluency and operators who want a dependable desk reference. It supports the Linux "
     "proficiency Ranger treats as a hard prerequisite for every board."},
    {"slug": "man7-linux-man-pages", "title": "Linux man-pages",
     "category": "linux-sysadmin", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "Linux man-pages project (man7.org)", "topic": "Documentation, Syscalls, Utilities",
     "url": "https://man7.org/linux/man-pages/",
     "source_attribution": "Linux man-pages project, maintained by Michael Kerrisk",
     "summary": "The authoritative online edition of the Linux manual pages documenting system "
     "calls, library functions, special files, configuration formats and command-line utilities. "
     "It matters because reading primary documentation, rather than tutorials, is the behaviour "
     "Ranger expects when a candidate meets an unfamiliar tool or syscall under time pressure. It "
     "benefits analysts verifying exact flag semantics and engineers reasoning about syscall "
     "behaviour during investigation or exploitation. It reinforces Ranger's documentation-driven "
     "method: consult the specification, confirm behaviour, then act on evidence."},
    {"slug": "linux-journey", "title": "Linux Journey",
     "category": "linux-sysadmin", "rtype": "external-course", "level": "foundational",
     "publisher": "Linux Journey", "topic": "Linux, Processes, Networking basics",
     "url": "https://linuxjourney.com/",
     "source_attribution": "Linux Journey contributors",
     "summary": "A concise, modular walkthrough of Linux fundamentals spanning the shell, "
     "filesystem, text processing, processes, user management, networking basics and logging, with "
     "short exercises per topic. It matters because Ranger does not run beginner laboratories, so "
     "applicants are expected to reach baseline competence on their own before applying. It benefits "
     "newcomers assembling a study path and experienced users filling specific gaps such as "
     "process signals or permission bits. It aligns with Ranger's self-directed preparation model "
     "and the independent problem-solving the program measures."},
    {"slug": "gnu-bash-manual", "title": "GNU Bash Reference Manual",
     "category": "linux-sysadmin", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "GNU Project, Free Software Foundation", "topic": "Bash, Scripting, Automation",
     "url": "https://www.gnu.org/software/bash/manual/",
     "source_attribution": "GNU Project, Free Software Foundation",
     "summary": "The official specification of the Bash shell covering syntax, parameter and "
     "variable expansion, conditional constructs, functions, job control and the full builtin "
     "command set. It matters because Ranger automation, grading harnesses and lab provisioning are "
     "expressed in shell, and correct quoting, expansion and exit-status handling separate reliable "
     "scripts from fragile ones. It benefits engineers writing robust automation and analysts who "
     "need to read and trust existing scripts. It underpins the Bash and automation competence "
     "Ranger expects candidates to apply without supervision."},

    # ---- B. Networking & Infrastructure -------------------------------------
    {"slug": "cloudflare-learning-center", "title": "Cloudflare Learning Center",
     "category": "networking", "rtype": "reference-guide", "level": "foundational",
     "publisher": "Cloudflare", "topic": "DNS, TLS, DDoS, Web",
     "url": "https://www.cloudflare.com/learning/",
     "source_attribution": "Cloudflare",
     "summary": "A broad library of vendor-neutral explainers covering DNS, TLS, HTTP, DDoS, bots "
     "and common web and network attacks, written for practitioners who need accurate mental "
     "models quickly. It matters because Ranger investigations constantly touch DNS resolution, "
     "TLS behaviour and web protocol mechanics, and precise terminology prevents misdiagnosis. It "
     "benefits SOC analysts building fluency in protocols they will triage and engineers who need a "
     "shared vocabulary for architecture discussions. It supports the networking fundamentals "
     "Ranger assumes across the blue and red boards."},
    {"slug": "tcpip-guide", "title": "The TCP/IP Guide",
     "category": "networking", "rtype": "technical-book", "level": "intermediate",
     "publisher": "Charles M. Kozierok", "topic": "TCP/IP, UDP, Routing, Protocols",
     "url": "http://www.tcpipguide.com/free/",
     "source_attribution": "Charles M. Kozierok, The TCP/IP Guide",
     "summary": "A comprehensive, freely readable reference on the TCP/IP protocol suite, detailing "
     "addressing, subnetting, routing, the transport layer, and core application protocols with "
     "diagrams and packet-level explanation. It matters because packet analysis, lateral movement "
     "and detection all depend on understanding how TCP, UDP and routing actually behave on the "
     "wire. It benefits analysts reconstructing network activity and red operators reasoning about "
     "reachability and segmentation. It deepens the protocol knowledge Ranger expects when "
     "candidates analyze captures or design and evade detections."},
    {"slug": "openssh-manual", "title": "OpenSSH Manual Pages",
     "category": "networking", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "The OpenBSD project (OpenSSH)", "topic": "SSH, Keys, Secure connectivity",
     "url": "https://www.openssh.com/manual.html",
     "source_attribution": "The OpenBSD Project, OpenSSH",
     "summary": "The primary manuals for the OpenSSH suite, documenting the client and server, key "
     "generation and agents, configuration files, port forwarding and certificate authentication. "
     "It matters because secure remote access underpins lab connectivity and because misconfigured "
     "SSH is a recurring finding in both defensive review and offensive assessment. It benefits "
     "operators hardening access, analysts interpreting authentication telemetry, and engineers "
     "automating key-based workflows. It supports the secure connectivity practices Ranger expects "
     "candidates to apply when reaching lab infrastructure."},
    {"slug": "wireshark-users-guide", "title": "Wireshark User's Guide",
     "category": "networking", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "Wireshark Foundation", "topic": "Packet analysis, PCAP, Protocols",
     "board": 2, "role": "threat-hunter",
     "url": "https://www.wireshark.org/docs/wsug_html_chunked/",
     "source_attribution": "Wireshark Foundation",
     "summary": "The official guide to Wireshark covering capture, display and capture filters, "
     "protocol dissection, stream reassembly, statistics and exporting objects from traffic. It "
     "matters because network evidence is central to hunting and incident response, and fluency "
     "with filters and dissectors turns a raw capture into a defensible finding. It benefits threat "
     "hunters validating hypotheses against packets and responders reconstructing an intrusion from "
     "network data. It directly supports Ranger's hunting and investigation boards where candidates "
     "must extract and justify conclusions from captures."},
    {"slug": "rfc-9293-tcp", "title": "RFC 9293: Transmission Control Protocol",
     "category": "networking", "rtype": "technical-standard", "level": "advanced",
     "publisher": "IETF", "topic": "TCP, Standards, Transport",
     "url": "https://www.rfc-editor.org/rfc/rfc9293",
     "source_attribution": "Internet Engineering Task Force (IETF)",
     "summary": "The consolidated IETF standard that specifies the Transmission Control Protocol, "
     "including the connection state machine, segment format, flow and congestion control and "
     "error handling. It matters because reading the normative specification, rather than a summary, "
     "is how a Ranger candidate settles ambiguous behaviour when analyzing anomalous sessions or "
     "crafting traffic. It benefits analysts explaining unusual flag sequences and operators "
     "reasoning precisely about connection handling. It models the primary-source discipline Ranger "
     "expects when a secondary explanation is insufficient or disputed."},

    # ---- C. Security Operations & SIEM --------------------------------------
    {"slug": "opensearch-docs", "title": "OpenSearch Documentation",
     "category": "secops-siem", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "OpenSearch Project", "topic": "OpenSearch, Indexing, Search",
     "board": 1, "role": "soc-analyst",
     "url": "https://docs.opensearch.org/latest/",
     "source_attribution": "OpenSearch Project",
     "summary": "The official documentation for OpenSearch, the search and analytics engine that "
     "backs the program's shared SIEM, covering indexing, mappings, ingestion, security and cluster "
     "operation. It matters because Ranger's blue boards investigate telemetry inside an OpenSearch "
     "backed console, and understanding how data is indexed and queried is what makes an "
     "investigation efficient and correct. It benefits SOC analysts learning the platform they will "
     "work in and detection engineers shaping data for rules. It maps to the Security Operations and "
     "SIEM competence the early boards assess."},
    {"slug": "opensearch-query-dsl", "title": "OpenSearch Query DSL",
     "category": "secops-siem", "rtype": "technical-documentation", "level": "advanced",
     "publisher": "OpenSearch Project", "topic": "Query DSL, Search, Detection",
     "board": 2, "role": "threat-hunter",
     "url": "https://docs.opensearch.org/latest/query-dsl/",
     "source_attribution": "OpenSearch Project",
     "summary": "The reference for the OpenSearch query domain-specific language, covering term, "
     "full-text, boolean, range and aggregation queries used to search and summarize security "
     "telemetry. It matters because precise querying is the core mechanic of alert triage and "
     "threat hunting, where a sloppy query hides the very events that prove or disprove a "
     "hypothesis. It benefits analysts constructing exact searches and hunters building aggregations "
     "that surface outliers. It directly supports the hunting and triage work Ranger grades, where "
     "candidates must turn a question into a defensible query and result."},
    {"slug": "opensearch-dashboards", "title": "OpenSearch Dashboards Documentation",
     "category": "secops-siem", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "OpenSearch Project", "topic": "Dashboards, Visualization, Discover",
     "board": 1, "role": "soc-analyst",
     "url": "https://docs.opensearch.org/latest/dashboards/",
     "source_attribution": "OpenSearch Project",
     "summary": "The guide to OpenSearch Dashboards, the analyst-facing interface for exploring "
     "data, building visualizations and saved searches, and navigating indices through Discover. "
     "It matters because the console a Ranger uses to triage alerts and pivot through evidence is "
     "built on Dashboards, and knowing its query bar, filters and field behaviour speeds every "
     "investigation. It benefits SOC analysts who live in the interface daily and engineers "
     "preparing views for a cohort. It supports the practical SIEM fluency the SOC analyst board "
     "expects from day one."},
    {"slug": "sigmahq-sigma", "title": "Sigma Detection Rules",
     "category": "secops-siem", "rtype": "open-source-project", "level": "advanced",
     "publisher": "SigmaHQ", "topic": "Detection, Sigma, Rules",
     "board": 3, "role": "detection-engineer",
     "url": "https://github.com/SigmaHQ/sigma",
     "source_attribution": "SigmaHQ and contributors",
     "summary": "The open, vendor-neutral format for writing detection rules against log data, with "
     "a large community rule set and tooling to convert rules into backend queries. It matters "
     "because Ranger's detection board asks candidates to author portable detections that fire on "
     "real malicious behaviour while controlling false positives, which is exactly what Sigma "
     "formalizes. It benefits detection engineers learning rule structure, field logic and testing, "
     "and analysts who want to read existing rules critically. It maps to the detection engineering "
     "competence graded against a holdout dataset."},
    {"slug": "security-onion-docs", "title": "Security Onion Documentation",
     "category": "secops-siem", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "Security Onion Solutions", "topic": "Monitoring, IDS, Log analysis",
     "board": 2, "role": "threat-hunter",
     "url": "https://docs.securityonion.net/",
     "source_attribution": "Security Onion Solutions, LLC",
     "summary": "The documentation for Security Onion, an open platform for network security "
     "monitoring, log management and threat hunting that integrates sensors, detections and an "
     "analyst interface. It matters because it shows how the components Ranger exercises separately, "
     "capture, detection rules and a SIEM, fit together into a monitoring pipeline a defender "
     "actually runs. It benefits hunters and analysts who want context for how alerts are produced "
     "and triaged end to end. It reinforces the operational picture behind Ranger's security "
     "operations and hunting boards."},

    # ---- D. Threat Intelligence & Vulnerability Research --------------------
    {"slug": "mitre-attack", "title": "MITRE ATT&CK",
     "category": "threat-intel", "rtype": "threat-intelligence", "level": "intermediate",
     "publisher": "MITRE", "topic": "ATT&CK, TTPs, Adversary techniques",
     "board": 1, "role": "soc-analyst",
     "url": "https://attack.mitre.org/",
     "source_attribution": "MITRE Corporation",
     "summary": "The globally used knowledge base of adversary tactics, techniques and procedures "
     "observed in real intrusions, organized into a matrix with detection and mitigation guidance "
     "per technique. It matters because Ranger maps every board, scenario and detection to ATT&CK, "
     "so a shared technique vocabulary is the connective tissue across triage, hunting, detection "
     "and red teaming. It benefits analysts classifying activity, engineers scoping detections and "
     "operators planning attack paths. It is foundational to how Ranger describes what candidates "
     "must observe, detect and reproduce."},
    {"slug": "cisa-kev", "title": "CISA Known Exploited Vulnerabilities Catalog",
     "category": "threat-intel", "rtype": "threat-intelligence", "level": "foundational",
     "publisher": "Cybersecurity and Infrastructure Security Agency (CISA)",
     "topic": "KEV, Exploitation, Prioritization",
     "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "source_attribution": "Cybersecurity and Infrastructure Security Agency (CISA)",
     "summary": "An authoritative, continuously maintained list of vulnerabilities with reliable "
     "evidence of active exploitation in the wild, each tied to a CVE and remediation guidance. "
     "It matters because Ranger's curriculum tracks what is actually being exploited now, turning "
     "catalog entries into reproducible patch and detection tasks rather than theoretical risk. It "
     "benefits analysts prioritizing by real-world exploitation and engineers deciding what to "
     "detect first. It is a primary, time-sensitive source that candidates should consult directly "
     "rather than through secondary summaries."},
    {"slug": "nist-nvd", "title": "National Vulnerability Database",
     "category": "threat-intel", "rtype": "reference-guide", "level": "intermediate",
     "publisher": "NIST", "topic": "NVD, CVE, CVSS",
     "url": "https://nvd.nist.gov/",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "The United States government repository of standards-based vulnerability data, "
     "enriching CVE records with severity scores, affected product identifiers and references. It "
     "matters because disciplined vulnerability research depends on authoritative metadata when "
     "assessing exposure, and Ranger expects candidates to reason from the record rather than a "
     "headline. It benefits analysts correlating a finding to affected products and engineers "
     "weighing severity against context. It supports the vulnerability prioritization skills the "
     "threat intelligence and detection work relies on."},
    {"slug": "cve-program", "title": "CVE Program",
     "category": "threat-intel", "rtype": "reference-guide", "level": "foundational",
     "publisher": "The CVE Program (MITRE and partners)", "topic": "CVE, Identifiers, Disclosure",
     "url": "https://www.cve.org/",
     "source_attribution": "The CVE Program, operated by MITRE with CNA partners",
     "summary": "The home of the Common Vulnerabilities and Exposures program, which assigns the "
     "canonical identifiers used to name and track individual vulnerabilities across the industry. "
     "It matters because every detection, patch task and threat report in Ranger references CVE "
     "identifiers, and understanding how records are created, scoped and updated prevents "
     "misattribution. It benefits analysts tracing a report back to its authoritative record and "
     "engineers reconciling vendor advisories. It grounds the common identifier scheme that ties "
     "threat intelligence, vulnerability research and detection together."},
    {"slug": "mitre-d3fend", "title": "MITRE D3FEND",
     "category": "threat-intel", "rtype": "reference-guide", "level": "advanced",
     "publisher": "MITRE", "topic": "Defensive techniques, Countermeasures",
     "board": 3, "role": "detection-engineer",
     "url": "https://d3fend.mitre.org/",
     "source_attribution": "MITRE Corporation",
     "summary": "A knowledge graph of defensive countermeasures that maps specific defensive "
     "techniques to the offensive techniques they address, complementing ATT&CK from the blue side. "
     "It matters because Ranger expects defenders to reason about which concrete controls and "
     "detections counter a given adversary behaviour, not just to name the attack. It benefits "
     "detection engineers selecting countermeasures and responders justifying containment choices. "
     "It strengthens the mapping from observed technique to defensive action that the detection and "
     "incident response boards reward."},

    # ---- E. Incident Response & Digital Forensics ---------------------------
    {"slug": "nist-sp-800-61", "title": "NIST SP 800-61 Rev. 3, Incident Handling",
     "category": "ir-forensics", "rtype": "technical-standard", "level": "intermediate",
     "publisher": "NIST", "topic": "Incident handling, Lifecycle, Reporting",
     "board": 4, "role": "incident-responder",
     "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "The United States government guide to computer security incident handling, defining "
     "the incident lifecycle from preparation through detection, analysis, containment, eradication "
     "and post-incident activity. It matters because Ranger's incident response board grades a "
     "defensible process and reconstruction, and this publication is the reference process the "
     "program aligns to. It benefits responders structuring an investigation and candidates learning "
     "what good evidence handling and reporting look like. It directly underpins the methodology the "
     "IR board expects a candidate to apply and document."},
    {"slug": "volatility3-docs", "title": "Volatility 3 Documentation",
     "category": "ir-forensics", "rtype": "open-source-project", "level": "advanced",
     "publisher": "The Volatility Foundation", "topic": "Memory forensics, Analysis",
     "board": 4, "role": "incident-responder",
     "url": "https://volatility3.readthedocs.io/",
     "source_attribution": "The Volatility Foundation",
     "summary": "The documentation for Volatility 3, the open framework for extracting processes, "
     "network connections, injected code and other artefacts from memory images. It matters because "
     "memory analysis often holds the only evidence of in-memory tradecraft that leaves little on "
     "disk, and Ranger expects responders to recover and interpret it. It benefits incident "
     "responders building a timeline from volatile evidence and analysts confirming execution that "
     "logs alone miss. It supports the host investigation and forensic methodology competence the "
     "incident response board measures."},
    {"slug": "zeek-docs", "title": "Zeek Documentation",
     "category": "ir-forensics", "rtype": "open-source-project", "level": "advanced",
     "publisher": "The Zeek Project", "topic": "Network forensics, Monitoring",
     "board": 4, "role": "incident-responder",
     "url": "https://docs.zeek.org/",
     "source_attribution": "The Zeek Project",
     "summary": "The documentation for Zeek, a network analysis framework that turns traffic into "
     "rich, structured logs of connections, protocols and files for monitoring and forensics. It "
     "matters because Zeek logs give responders a high-signal record of network activity that is "
     "far easier to reason over than raw packets when reconstructing an intrusion. It benefits "
     "responders correlating host and network evidence and hunters building behavioural detections. "
     "It supports the network forensics and timeline work the incident response and hunting boards "
     "expect candidates to perform."},
    {"slug": "suricata-docs", "title": "Suricata Documentation",
     "category": "ir-forensics", "rtype": "open-source-project", "level": "advanced",
     "publisher": "Open Information Security Foundation (OISF)", "topic": "IDS, IPS, Signatures",
     "board": 3, "role": "detection-engineer",
     "url": "https://docs.suricata.io/",
     "source_attribution": "Open Information Security Foundation (OISF)",
     "summary": "The documentation for Suricata, an open intrusion detection and prevention engine "
     "that inspects traffic with signatures and protocol logic and emits alerts and metadata. It "
     "matters because network detections are a core defensive control, and Ranger expects engineers "
     "to understand how rules match, how to tune them and how alerts become evidence. It benefits "
     "detection engineers authoring and validating network rules and responders interpreting "
     "Suricata alerts during an incident. It supports both the detection engineering and incident "
     "response boards where network signatures appear."},
    {"slug": "velociraptor-docs", "title": "Velociraptor Documentation",
     "category": "ir-forensics", "rtype": "open-source-project", "level": "advanced",
     "publisher": "Velociraptor (Rapid7)", "topic": "Endpoint DFIR, Collection, Hunting",
     "board": 4, "role": "incident-responder",
     "url": "https://docs.velociraptor.app/",
     "source_attribution": "Velociraptor project (Rapid7)",
     "summary": "The documentation for Velociraptor, an endpoint tool for digital forensics and "
     "incident response that collects artefacts and runs hunts across hosts using its query "
     "language. It matters because scalable evidence collection and host hunting are central to "
     "modern IR, and Ranger expects responders to gather artefacts methodically rather than ad hoc. "
     "It benefits responders standardizing collection and analysts hunting for indicators across "
     "endpoints. It supports the evidence collection and host investigation competence the incident "
     "response board assesses."},

    # ---- F. Offensive Security & Adversary Emulation ------------------------
    {"slug": "mitre-attack-evaluations", "title": "MITRE ATT&CK Evaluations",
     "category": "offensive", "rtype": "research-publication", "level": "research",
     "publisher": "MITRE Engenuity", "topic": "Adversary emulation, Evaluation",
     "board": 5, "role": "red-teamer",
     "url": "https://attackevals.mitre-engenuity.org/",
     "source_attribution": "MITRE Engenuity",
     "summary": "Public results and methodology from MITRE Engenuity's evaluations of security "
     "products against emulated adversary behaviour mapped to ATT&CK. It matters because the "
     "evaluations model rigorous, technique-by-technique adversary emulation and transparent "
     "scoring, which mirrors how Ranger expects offensive work to be planned and evidenced. It "
     "benefits red operators studying realistic emulation plans and defenders learning how "
     "detections are judged against specific techniques. It informs the disciplined, documented "
     "approach to adversary emulation the red team and capstone boards expect."},
    {"slug": "atomic-red-team", "title": "Atomic Red Team",
     "category": "offensive", "rtype": "practical-exercise", "level": "intermediate",
     "publisher": "Red Canary", "topic": "Adversary emulation, Testing, ATT&CK",
     "board": 3, "role": "detection-engineer",
     "url": "https://github.com/redcanaryco/atomic-red-team",
     "source_attribution": "Red Canary and contributors",
     "summary": "A library of small, portable tests mapped to ATT&CK techniques that safely execute "
     "specific adversary behaviours so defenders can confirm whether their detections fire. It "
     "matters because Ranger grades detections against real behaviour, and atomic tests are a "
     "disciplined way to generate that behaviour and validate coverage. It benefits detection "
     "engineers verifying rules and red operators understanding technique execution at a primitive "
     "level. It bridges the offensive and detection boards by making the link between a technique "
     "and its observable telemetry concrete and repeatable."},
    {"slug": "owasp-wstg", "title": "OWASP Web Security Testing Guide",
     "category": "offensive", "rtype": "technical-standard", "level": "advanced",
     "publisher": "OWASP Foundation", "topic": "Web testing, AppSec, Methodology",
     "url": "https://owasp.org/www-project-web-security-testing-guide/",
     "source_attribution": "OWASP Foundation",
     "summary": "A comprehensive, community-maintained methodology for testing the security of web "
     "applications, organized by test category with concrete procedures and expected observations. "
     "It matters because structured, repeatable methodology is what separates professional security "
     "testing from ad hoc poking, which is the standard Ranger holds offensive work to. It benefits "
     "operators conducting authorized web assessments and defenders learning how applications are "
     "attacked and verified. It supports the security testing methodology competence the offensive "
     "boards expect candidates to apply and document."},
    {"slug": "ludus-docs", "title": "Ludus Documentation",
     "category": "offensive", "rtype": "technical-documentation", "level": "advanced",
     "publisher": "Ludus", "topic": "Range automation, Lab, Infrastructure",
     "board": 5, "role": "red-teamer",
     "url": "https://docs.ludus.cloud/",
     "source_attribution": "Ludus project",
     "summary": "The documentation for Ludus, an automation platform for building and managing "
     "isolated, reproducible cyber ranges from declarative definitions. It matters because Ranger "
     "provisions its isolated red-team environments through Ludus, so understanding range "
     "definitions, deployment and teardown explains how a candidate's lab is actually created and "
     "controlled. It benefits operators who want to reason about their range and engineers studying "
     "reproducible lab infrastructure. It provides technical context for the isolated-range model "
     "behind the offensive and capstone boards."},
    {"slug": "goad-game-of-active-directory", "title": "GOAD, Game of Active Directory",
     "category": "offensive", "rtype": "open-source-project", "level": "advanced",
     "publisher": "Orange Cyberdefense", "topic": "Active Directory, Attack paths, Lab",
     "board": 5, "role": "red-teamer",
     "url": "https://github.com/Orange-Cyberdefense/GOAD",
     "image": "/img/goad-architecture.png",
     "source_attribution": "GOAD project, Orange Cyberdefense. Topology diagram courtesy of the GOAD project.",
     "summary": "An intentionally vulnerable multi-domain Active Directory lab that chains realistic "
     "misconfigurations and trust relationships into practical attack paths across forests. It "
     "matters because Ranger's red-team boards are built on GOAD, so its domains, hosts and "
     "deliberate weaknesses are the terrain candidates must enumerate, exploit and move through. It "
     "benefits operators learning Active Directory attack paths and defenders studying how those "
     "paths appear in telemetry. It is the direct technical reference for the environment the "
     "offensive boards assess, from initial access to cross-forest compromise."},

    # ---- G. Engineering, Automation & Secure Development --------------------
    {"slug": "pro-git", "title": "Pro Git",
     "category": "engineering", "rtype": "technical-book", "level": "foundational",
     "publisher": "Scott Chacon, Ben Straub (Git project)", "topic": "Git, Version control",
     "url": "https://git-scm.com/book/en/v2",
     "source_attribution": "Scott Chacon and Ben Straub, the Git project",
     "summary": "The official, freely available book on Git, covering the object model, branching "
     "and merging, remotes, rebasing and collaboration workflows. It matters because every Ranger "
     "deliverable, from lab forks to detection rules, moves through Git, and the program's "
     "automated grading is driven by commits and pull requests. It benefits candidates who need "
     "reliable version-control habits and engineers reasoning about history and merges. It supports "
     "the Git and GitHub fluency Ranger assumes when candidates submit work and when the program "
     "measures it through the repository."},
    {"slug": "github-actions-docs", "title": "GitHub Actions Documentation",
     "category": "engineering", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "GitHub", "topic": "CI/CD, Automation, Workflows",
     "url": "https://docs.github.com/en/actions",
     "source_attribution": "GitHub",
     "summary": "The documentation for GitHub Actions, the workflow automation and continuous "
     "integration system that runs jobs in response to repository events. It matters because "
     "Ranger's lab grading and submission checks run as Actions workflows, so understanding "
     "triggers, jobs, runners and secrets explains how a candidate's work is validated "
     "automatically. It benefits engineers building reliable pipelines and candidates who want to "
     "understand how their submissions are checked. It supports the CI/CD and automated validation "
     "competence the program relies on for answer-free grading."},
    {"slug": "python-docs", "title": "Python Documentation",
     "category": "engineering", "rtype": "technical-documentation", "level": "intermediate",
     "publisher": "Python Software Foundation", "topic": "Python, Scripting, Standard library",
     "url": "https://docs.python.org/3/",
     "source_attribution": "Python Software Foundation",
     "summary": "The official Python documentation, including the language reference, the standard "
     "library and tutorials for the version used across security tooling. It matters because much "
     "defensive and offensive tooling, parsing and automation in Ranger is written in Python, and "
     "candidates are expected to read, adapt and write it rather than treat tools as black boxes. "
     "It benefits engineers automating analysis and candidates scripting against logs, APIs and "
     "artefacts. It supports the scripting and automation competence Ranger expects candidates to "
     "apply independently across the boards."},
    {"slug": "mit-missing-semester", "title": "The Missing Semester of Your CS Education",
     "category": "engineering", "rtype": "external-course", "level": "foundational",
     "publisher": "MIT", "topic": "Shell, Tooling, Workflow",
     "url": "https://missing.csail.mit.edu/",
     "source_attribution": "MIT (The Missing Semester of Your CS Education)",
     "summary": "A free MIT course covering the practical tooling often skipped in formal "
     "curricula: the shell, scripting, editors, version control, debugging and data wrangling. It "
     "matters because Ranger assumes candidates are fluent with the everyday tooling of a technical "
     "practitioner, and this course closes exactly those gaps efficiently. It benefits applicants "
     "preparing for self-directed work and operators sharpening command-line and debugging habits. "
     "It aligns with Ranger's expectation that candidates can configure their own environment and "
     "investigate problems with professional tooling before they apply."},
    {"slug": "owasp-asvs", "title": "OWASP Application Security Verification Standard",
     "category": "engineering", "rtype": "technical-standard", "level": "advanced",
     "publisher": "OWASP Foundation", "topic": "Secure development, Verification, AppSec",
     "url": "https://owasp.org/www-project-application-security-verification-standard/",
     "source_attribution": "OWASP Foundation",
     "summary": "A framework of testable application security requirements organized by verification "
     "level, used to specify and assess the security controls a piece of software should implement. "
     "It matters because secure development is part of the engineering competence Ranger values, "
     "and ASVS gives a concrete, auditable definition of what secure looks like rather than vague "
     "guidance. It benefits engineers building verifiable controls and assessors structuring a "
     "review. It supports the secure development and verification knowledge expected of candidates "
     "who build and evaluate tooling."},

    # ---- H. Security Frameworks & Research Standards ------------------------
    {"slug": "nist-csf", "title": "NIST Cybersecurity Framework",
     "category": "frameworks", "rtype": "technical-standard", "level": "foundational",
     "publisher": "NIST", "topic": "CSF, Governance, Risk",
     "url": "https://www.nist.gov/cyberframework",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "A widely adopted framework that organizes cybersecurity activity into core "
     "functions for governing, identifying, protecting, detecting, responding and recovering. It "
     "matters because Ranger situates hands-on technical work inside the professional language that "
     "auditors and organizations actually use, so candidates can connect a detection or response to "
     "its place in a program. It benefits practitioners who need to communicate technical findings "
     "to a governance audience and engineers aligning controls. It provides the professional "
     "framing Ranger expects alongside technical depth."},
    {"slug": "nist-sp-800-53", "title": "NIST SP 800-53 Rev. 5",
     "category": "frameworks", "rtype": "technical-standard", "level": "advanced",
     "publisher": "NIST", "topic": "Security controls, Privacy, Baselines",
     "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "The catalog of security and privacy controls used across United States federal "
     "systems and widely referenced in the private sector, organized into control families with "
     "enhancements. It matters because it is the authoritative vocabulary for the controls Ranger's "
     "technical work implements or tests, letting candidates tie a detection or hardening step to a "
     "recognized control. It benefits engineers mapping work to requirements and analysts framing "
     "gaps precisely. It anchors the frameworks and standards competence that distinguishes "
     "rigorous, communicable security engineering."},
    {"slug": "nist-sp-800-115", "title": "NIST SP 800-115, Security Testing and Assessment",
     "category": "frameworks", "rtype": "technical-standard", "level": "advanced",
     "publisher": "NIST", "topic": "Testing, Assessment, Methodology",
     "board": 5, "role": "red-teamer",
     "url": "https://csrc.nist.gov/pubs/sp/800/115/final",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "A technical guide to planning and conducting information security testing and "
     "assessment, covering review, identification and validation techniques and how to handle "
     "results responsibly. It matters because Ranger holds offensive and assessment work to a "
     "documented, repeatable standard, and this publication is a canonical reference for that "
     "discipline. It benefits operators structuring an authorized assessment and candidates "
     "learning to scope, execute and report testing defensibly. It supports the methodology and "
     "reporting rigor the offensive and capstone boards expect."},
    {"slug": "nist-sp-800-86", "title": "NIST SP 800-86, Forensic Techniques into IR",
     "category": "frameworks", "rtype": "technical-standard", "level": "advanced",
     "publisher": "NIST", "topic": "Forensics, Evidence, Incident response",
     "board": 4, "role": "incident-responder",
     "url": "https://csrc.nist.gov/pubs/sp/800/86/final",
     "source_attribution": "National Institute of Standards and Technology (NIST)",
     "summary": "A guide to integrating forensic techniques into incident response, covering the "
     "collection, examination, analysis and reporting of digital evidence from files, operating "
     "systems, network traffic and applications. It matters because Ranger's incident response "
     "board grades defensible evidence handling, and this publication defines the process and "
     "integrity expectations the program aligns to. It benefits responders standardizing their "
     "method and candidates learning how evidence stays admissible and reproducible. It reinforces "
     "the forensic methodology and evidence integrity the IR board assesses."},
    {"slug": "cisa-cpg", "title": "CISA Cross-Sector Cybersecurity Performance Goals",
     "category": "frameworks", "rtype": "technical-standard", "level": "foundational",
     "publisher": "Cybersecurity and Infrastructure Security Agency (CISA)",
     "topic": "Baseline controls, Prioritization",
     "url": "https://www.cisa.gov/cross-sector-cybersecurity-performance-goals",
     "source_attribution": "Cybersecurity and Infrastructure Security Agency (CISA)",
     "summary": "A prioritized, voluntary baseline of high-impact cybersecurity practices mapped to "
     "common frameworks and to the ATT&CK techniques they help address. It matters because Ranger "
     "connects technical detections and defenses to the practical, prioritized controls "
     "organizations are urged to adopt, helping candidates see why a given defense matters. It "
     "benefits engineers prioritizing effort and analysts explaining the impact of a gap in plain "
     "terms. It supports the frameworks competence that lets candidates place technical work in an "
     "operational risk context."},
]

assert len(CATALOG) == 40, "expected 40 external catalog entries"


# --- 4 original Qwalora publications (status=draft, review-gated) ------------
# These are NOT published publicly until technical review. They carry long-form
# body content (markdown) and are inserted with status "draft". Each is clearly
# marked DRAFT and distinguishes approved policy from proposed procedure. No
# grading secrets, answer keys or internal assessment logic are disclosed, and
# no research findings are fabricated.
ORIGINALS = [
    {
        "slug": "ranger-linux-readiness-standard",
        "title": "Ranger Linux Readiness Standard",
        "category": "linux-sysadmin", "rtype": "research-publication", "level": "foundational",
        "publisher": "Qwalora LLC, Ranger program",
        "topic": "Readiness, Linux, Prerequisites",
        "source_attribution": "Qwalora LLC, Ranger program",
        "summary": "The Linux baseline Ranger expects before admission: the system administration, "
        "filesystem, shell, service and networking competencies a candidate must already hold, with "
        "readiness scenarios and recommended external references. This is a readiness standard, not "
        "a beginner course.",
        "body": """> **DRAFT. Pending technical review. Not an approved policy until published.**

# Ranger Linux Readiness Standard

Qwalora Ranger is a documentation-driven program. It does not teach Linux from
zero. This standard states the Linux baseline a candidate is expected to hold
**before** admission, so that effort inside the program goes to security
engineering rather than operating-system basics.

## Who this is for

Applicants assessing their own readiness, and reviewers setting a consistent bar.
It is a statement of expected competence, not a curriculum.

## Required competencies

**System administration.** Install and update packages, manage users and groups,
read and edit configuration under `/etc`, and understand the filesystem hierarchy.

**Filesystem and permissions.** Reason about ownership, permission bits, and
special bits; use `chmod`, `chown`, and `umask` deliberately; follow symlinks and
mount points without confusion.

**Shell and Bash.** Navigate and manipulate files; use redirection and pipelines;
write a readable script with variables, conditionals, loops and functions; quote
correctly; and check exit status.

**systemd and process management.** Inspect and control services with
`systemctl`; read unit files; list and signal processes; and interpret resource
usage with standard tools.

**Networking and troubleshooting.** Configure an interface, test reachability,
inspect listening sockets, resolve names, and read a capture at a basic level.

**System logging.** Locate and read logs under `journald` and `/var/log`, and
follow an event across services.

## Readiness scenarios

A ready candidate can, without a walkthrough: recover a service that fails to
start by reading its unit and journal; find which process holds a port and stop
it safely; fix a permissions problem that blocks a service; and reconstruct a
short sequence of events from logs.

## Recommended external references

The Linux Command Line (Shotts); the GNU Bash Reference Manual; the Linux
man-pages; Introduction to Linux (LFS101); and The Missing Semester (MIT). These
are preparation resources, not a guarantee of admission.

## Admission expectation

Linux proficiency is a prerequisite, assessed as part of the overall bar. This
standard does not define the full admission process; see the Candidate Technical
Preparation Guide.
""",
    },
    {
        "slug": "ranger-candidate-technical-preparation-guide",
        "title": "Ranger Candidate Technical Preparation Guide",
        "category": "frameworks", "rtype": "research-publication", "level": "foundational",
        "publisher": "Qwalora LLC, Ranger program",
        "topic": "Preparation, Admission, Self-assessment",
        "source_attribution": "Qwalora LLC, Ranger program",
        "summary": "How to prepare for Ranger: the self-directed learning philosophy, the technical "
        "prerequisites, a practical readiness self-assessment, recommended free resources, and the "
        "application and qualification process. Distinguishes approved policy from proposed Ranger "
        "Scholars procedures.",
        "body": """> **DRAFT. Pending technical review. Proposed items are labelled; do not treat them as approved policy.**

# Ranger Candidate Technical Preparation Guide

## Learning philosophy

Ranger is self-directed and documentation-driven. There are no instructor-led
lectures, simplified labs, or guided solutions. Candidates investigate unfamiliar
problems independently, read primary documentation, and produce evidence that is
measured by the program.

## Eligibility

**Proposed (pending review):** a minimum age of 13 for the Ranger Scholars track.
Age and admission procedures for Scholars are proposed and are not approved policy
until confirmed and published by Qwalora.

## Technical prerequisites

Candidates are expected to hold, before applying: Linux proficiency (see the
Ranger Linux Readiness Standard); networking fundamentals (TCP/IP, DNS, routing,
and the ability to read a capture); comfort with Git and the command line; and
the ability to script in Bash and read Python.

## Independent preparation

Preparation is the candidate's own responsibility. Completing any external course
does **not** guarantee admission, and no external provider is a Ranger partner
unless Qwalora states so explicitly.

## Recommended free resources

Introduction to Linux (LFS101); The Linux Command Line; The Missing Semester
(MIT); Pro Git; the Python documentation; MITRE ATT&CK; and the NIST
Cybersecurity Framework. The Resource Library lists these with full context.

## Readiness self-assessment

Before applying, confirm you can: operate a Linux host without a walkthrough;
reconstruct events from logs; write and debug a non-trivial shell script; use Git
for real work; query a dataset to answer a specific question; and read a standard
or RFC to settle a technical question.

## Application and qualification

Admission is reviewed by the program. Candidates apply, are approved by a
reviewer, and then progress board by board. Progress is program-measured and
cryptographically signed. The exact qualification bar and board sequence are
described in program materials.
""",
    },
    {
        "slug": "ranger-technical-assessment-evidence-standards",
        "title": "Ranger Technical Assessment & Evidence Standards",
        "category": "frameworks", "rtype": "research-publication", "level": "intermediate",
        "publisher": "Qwalora LLC, Ranger program",
        "topic": "Assessment, Evidence integrity, Signatures",
        "source_attribution": "Qwalora LLC, Ranger program",
        "summary": "How Ranger assesses work and protects evidence integrity: automated grading, "
        "technical deliverables, cryptographic signatures, qualification requirements and "
        "accountability, at a level that never exposes grading secrets, answer keys or internal "
        "assessment logic.",
        "body": """> **DRAFT. Pending technical review. Verify all implementation details against the current backend before publishing. Discloses no secrets, hidden tests, answer keys, or internal grading logic.**

# Ranger Technical Assessment & Evidence Standards

## Principles

Ranger measures competence from evidence, not self-report. Two channels combine:
an automated, answer-free objective measurement, and human review of written
technical deliverables. A board clears only when both standards are met.

## Automated assessment

Objective grading is performed by the program, not by the candidate's own tooling.
Each candidate works a scenario seeded uniquely to them; the program re-measures
the result independently. The grading is designed to be un-gameable: scenarios do
not repeat for a returning candidate, and the objective measure is reproducible
from the seed. Hidden grading tests, answer keys and internal scoring logic are
never disclosed.

## Technical deliverables

Candidates submit written analysis alongside the objective result: what was
found, how, and the supporting evidence. Deliverables are reviewed for technical
correctness and defensibility, not length.

## Evidence integrity and signatures

Cleared boards and credentials are sealed with Ed25519 digital signatures over a
canonical record. Anyone can verify a credential independently against the
program's public key, so a result cannot be forged or altered after the fact.
Certificate validity is time-bounded and verifiable.

## Qualification and accountability

Progress is board by board, SOC analyst to capstone. The qualification bar is
high and is applied consistently through reviewer approval and the signed record.
Accountability is built in: every cleared board and issued credential is signed
and independently checkable.

## Independent troubleshooting and documentation

Candidates are expected to resolve unfamiliar problems without guided solutions
and to document their reasoning to a professional standard. The assessment rewards
method and evidence, aligned with the forensic and testing standards in the
Resource Library.
""",
    },
    {
        "slug": "from-known-exploitation-to-defensive-investigation",
        "title": "From Known Exploitation to Defensive Investigation",
        "category": "threat-intel", "rtype": "research-publication", "level": "research",
        "publisher": "Qwalora LLC, Ranger program",
        "topic": "CVE, KEV, ATT&CK, Detection, Case study",
        "source_attribution": "Qwalora LLC, Ranger program. Public sources cited inline.",
        "summary": "An original analytical walkthrough of how a documented, actively exploited "
        "vulnerability connects to defensive telemetry, detection hypotheses and investigation, "
        "using CVE-2021-44228 (Log4Shell) as a public case study with authoritative citations. No "
        "reproduction is claimed.",
        "body": """> **DRAFT. Pending technical review. This is an analytical walkthrough built from public sources. It does not claim that Ranger has reproduced the vulnerability, and reports no original exploitation findings.**

# From Known Exploitation to Defensive Investigation

Defenders rarely start from a blank page. A documented vulnerability already
carries an identifier, exploitation evidence, and a mapping to adversary
technique. This article traces that chain, from a public record to defensive
investigation, using one well-documented case study.

## The chain

**CVE record.** A vulnerability is named by a CVE identifier and described, with
severity and affected products, in the National Vulnerability Database.

**Exploitation evidence.** When there is reliable evidence of active exploitation,
the vulnerability appears in CISA's Known Exploited Vulnerabilities catalog, which
raises its priority from theoretical to observed.

**Adversary technique.** The behaviour an attacker uses maps to one or more MITRE
ATT&CK techniques, giving defenders a shared label and detection guidance.

**Observable telemetry.** Each technique leaves traces in logs, network data or
memory. Defensive work is the disciplined search for those traces.

## Case study: CVE-2021-44228 (Log4Shell)

CVE-2021-44228 is a remote code execution flaw in Apache Log4j 2, disclosed in
December 2021 and recorded in the NVD
(https://nvd.nist.gov/vuln/detail/CVE-2021-44228). It is listed in the CISA KEV
catalog as actively exploited
(https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and the Apache
Logging project published guidance and fixed releases
(https://logging.apache.org/log4j/2.x/security.html).

The exploitation pattern maps cleanly to ATT&CK: a crafted string in attacker
controlled input triggers a JNDI lookup, leading to outbound resolution and a
fetch of attacker-hosted code, consistent with Exploitation of a Public-Facing
Application (T1190) and Command and Scripting Interpreter execution that follows.

## Observable telemetry and detection hypotheses

From the technique, a defender derives hypotheses to test, not conclusions to
assume:

- Application logs containing the characteristic `jndi:` lookup pattern in request
  fields, headers or user-agent strings.
- Unexpected outbound LDAP, RMI or DNS from an application server shortly after a
  request, suggesting a JNDI lookup to attacker infrastructure.
- A Java process spawning a shell or downloading a payload, visible in process and
  network telemetry.

Each hypothesis becomes a query against the SIEM and a candidate detection, which
is then validated against known-good and known-bad data to control false
positives.

## Defensive validation

A detection is only trustworthy once tested. Using a safe, authorized method to
generate the behaviour (for example an atomic test mapped to the technique) a
defender confirms the detection fires on the behaviour and does not fire on
benign traffic. This closes the loop from a public record to a verified defensive
control.

## Why this matters for Ranger

This is the exact motion the program grades: start from what is actually being
exploited, map it to technique and telemetry, form a hypothesis, query the data,
and validate a detection with evidence. It connects threat intelligence, security
operations, detection engineering and incident response into one defensible
workflow.

## References

- NVD, CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CISA Known Exploited Vulnerabilities Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Apache Log4j Security: https://logging.apache.org/log4j/2.x/security.html
- MITRE ATT&CK T1190: https://attack.mitre.org/techniques/T1190/
""",
    },
]


# --- Original research portfolio (QR-RES-*) ---------------------------------
# Internal Qwalora research publications. Each leads to a substantive on-site
# article (body below); external standards appear only as references. These are
# inserted with status="draft" (not public) and maturity reflecting how far the
# work has actually progressed. They are NEVER auto-approved: an authorized
# reviewer promotes a publication to status="published" in the admin.
_REPO = "https://github.com/qwalora/qwalora-cyber-range/tree/main/research"
_RAW = "https://github.com/qwalora/qwalora-cyber-range/blob/main/research"

QR_RES_002_VERIFICATION = {
    "publication_id": "QR-RES-002", "version": "1.0.0",
    "execution": {
        "status": "executed",
        "environment": "Linux / Python 3.13.16 (single cloud container)",
        "host_note": "target and verifier are separate OS processes on 127.0.0.1",
        "source_commit": "951ad43ce228442ce615ec3edc2d9fd184f0aaf9",
        "started_at": "2026-10-15T03:26:07Z", "completed_at": "2026-10-15T03:26:09Z",
    },
    "tests": {"total": 26, "passed": 26, "failed": 0, "inconclusive": 0, "pytest_exit_code": 0},
    "scenarios": {"count": 11, "verdict_matches_requirement": 11,
                  "verdict_tally": {"PASS": 2, "FAIL": 8, "INCONCLUSIVE": 1}},
    "independent_verification": {
        "performed": True,
        "verifier": "separate verifier process with its own Ed25519 key",
        "method": "verifier-generated run_id+nonce, active loopback probing, "
                  "signature + run-binding + replay intake checks; verdicts a pure "
                  "function of (requirement, observations)",
        "trust_boundary": "process isolation on one host (key never leaves the verifier "
                          "process); NOT container/VM isolation against a host-privileged target",
    },
    "review": {"technical_status": "pending_technical_review",
               "approved_by": None, "approved_at": None,
               "note": "Produced by Qwalora's automated research tooling; pending independent "
                       "human technical review and publication approval. Not self-approved."},
}

PUBLICATIONS = [
    {
        "pub_id": "QR-RES-002",
        "slug": "adversarial-authorization-and-evidence-verification",
        "title": "Adversarial Authorization and Evidence Verification",
        "category": "frameworks", "rtype": "research-publication", "level": "research",
        "pub_type": "evaluated-artifact",
        "collection": "A. Adversarial Verification & Evidence Integrity",
        "version": "1.0.0", "maturity": "technical-review",
        "publisher": "Qwalora LLC, Ranger research practice",
        "topic": "Authorization, Evidence integrity, Verification, ATT&CK T1078",
        "board": 1, "role": "detection-engineer",
        "source_attribution": "Qwalora LLC, Ranger research practice",
        "related": "QR-RES-001,QR-RES-003,QR-RES-017",
        "artifacts": [
            {"label": "Source (target, verifier, evidence)", "url": _REPO + "/QR-RES-002/qr_res_002"},
            {"label": "Test suite", "url": _REPO + "/QR-RES-002/tests"},
            {"label": "Verification record", "url": _RAW + "/QR-RES-002/evidence/verification.json"},
            {"label": "Recorded observations", "url": _RAW + "/QR-RES-002/evidence/scenarios.json"},
            {"label": "Evidence manifest (sha256)", "url": _RAW + "/QR-RES-002/evidence/manifest.sha256"},
            {"label": "Reproduction instructions (README)", "url": _RAW + "/QR-RES-002/README.md"},
        ],
        "refs": [
            {"label": "MITRE ATT&CK T1078: Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"},
            {"label": "OWASP API Security Top 10: Broken Object Level Authorization",
             "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
            {"label": "NIST SP 800-115: Technical Guide to Information Security Testing",
             "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
            {"label": "RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)",
             "url": "https://www.rfc-editor.org/rfc/rfc8032"},
        ],
        "verification": QR_RES_002_VERIFICATION,
        "summary": "An independent, out-of-process verifier probes a target application and adjudicates "
        "eleven authorization and evidence-integrity conditions from observed behavior, not from the "
        "target's self-report. Verdicts are a pure function of (requirement, observations); evidence is "
        "signature-, run-, and replay-protected. The reference run recorded 26 of 26 tests passing and "
        "11 of 11 verdicts matching the security requirement, with an honest process-isolation trust "
        "boundary. An evaluated engineering artifact, pending independent technical review.",
        "body": r"""## Technical abstract

A competence assessment that trusts a candidate's own claims about their own system
is unfalsifiable. This work builds a target application and an independent verifier
that runs in a separate process, generates its own signing key, actively probes the
target, and decides PASS, FAIL, or INCONCLUSIVE for eleven authorization and
evidence-integrity conditions from what it observes. Verdicts never read the scenario
label. Evidence is bound to the assessment run and protected against tampering and
replay. The reference run recorded 26 of 26 automated tests passing and 11 of 11
verdicts matching the stated security requirement.

## Threat model and engineering objective

Decide, from outside the target, whether an authorization requirement was actually
enforced, and whether the evidence of that decision can be trusted. The adversary is
the target itself: it may be misconfigured, buggy, or actively dishonest, and it may
attempt to submit evidence from another run, alter signed evidence, or replay stale
evidence. Behavior classes map to MITRE ATT&CK T1078 (valid/spoofed accounts) and the
OWASP BOLA class (broken object-level authorization).

## System topology

Two processes on one host. The target binds a loopback port; the verifier runs
separately and reaches the target only over `http://127.0.0.1:<port>`. The verifier
generates an Ed25519 keypair in its own memory; the private key is never serialized
or transmitted.

## Environment specifications

- Python 3.11+ (reference run on 3.13.16), standard library plus `cryptography` and `pytest`.
- No external network beyond loopback. No Docker required for this artifact.
- Deterministic: the harness launches and tears down the target per scenario.

## Exact experiment commands

```
pip install cryptography pytest
python run_experiment.py     # runs tests + all scenarios, writes evidence/
python -m pytest -v          # tests only
```

## Adversarial scenarios

| Case | Security condition | Required verdict |
|------|--------------------|------------------|
| AV-01 | Correct authorization | PASS |
| AV-02 | Anonymous access to protected data | FAIL |
| AV-03 | Cross-user object access (BOLA) | FAIL |
| AV-04 | Spoofed administrative authority | FAIL |
| AV-05 | Protection removed during the observation interval | FAIL |
| AV-06 | Sensitive data in an error response | FAIL |
| AV-07 | Evidence submitted from the wrong run | FAIL (rejected) |
| AV-08 | Signed evidence changed after signing | FAIL (rejected) |
| AV-09 | Valid but stale evidence replayed | FAIL (rejected) |
| AV-10 | Alternative valid implementation (404 resource-hiding) | PASS |
| AV-11 | Critical observations unavailable | INCONCLUSIVE |

The adjudicator receives only `(requirement, observations)`. It never sees the scenario
id or the expected verdict, so a verdict cannot be hardcoded to a scenario name. An
explicit anti-hardcoding test runs the AV-02 requirement against a correct target and
asserts the verdict flips to PASS, proving verdicts track observed behavior.

## Detection and telemetry analysis

Each requirement is decided from concrete observations: HTTP status, response body, and
whether protected object data was disclosed. AV-05 samples the protected object across
the observation interval and fails if any probe within the window saw data without
authentication. AV-06 fails if a known secret marker appears in any error body. AV-10
accepts a 404 resource-hiding denial as satisfying the no-disclosure requirement,
showing the verdict keys on the security property rather than a specific status code.

## Defensive implementation (evidence intake)

Evidence counts only after three ordered checks: Ed25519 signature over a canonical
serialization using the verifier's own key; run binding to this run's `run_id` and
unpredictable `nonce` (defeats cross-run submission); and freshness by unique
`evidence_id` (defeats replay). Missing critical observations yield INCONCLUSIVE, never
a silent PASS.

## Verification evidence

The orchestrator records, under `evidence/`: the real pytest output and exit code,
per-scenario observations and verdicts, the verifier-signed evidence records, a sha256
manifest over artifacts and source modules, and a machine-readable verification record
anchored to the source commit. An independent re-check confirmed all eleven signatures
valid, all eleven manifest hashes matched, and that a one-byte mutation invalidates the
signature.

## Measured results (reference run)

- Tests: 26 of 26 passed, pytest exit code 0.
- Scenario verdicts: 11 of 11 match the security requirement (PASS 2, FAIL 8, INCONCLUSIVE 1).
- Source commit: `951ad43ce228442ce615ec3edc2d9fd184f0aaf9`.
- Environment: Linux / Python 3.13.16, single cloud container.

## Failure analysis, limitations, and threats to validity

- **Trust boundary is process isolation, not VM or container isolation.** The verifier's
  private key never leaves its process, which defeats HTTP-level misbehavior, tampering,
  and replay. It does not defeat a target with same-user host access that could read the
  verifier's memory. Container or VM isolation with network and privilege boundaries is
  proposed follow-up and was **not executed**: this environment has no running Docker daemon.
- **Determinism, not statistics.** Eleven deterministic scenarios demonstrate specific
  conditions; no false-positive or false-negative rate over a population is claimed.
  QR-RES-005 is the benchmark that would measure rates.
- **Synthetic data only.** No real credentials, users, or production systems are involved.

## Conclusions

An out-of-process verifier can correctly adjudicate the eleven authorization and
evidence-integrity conditions from observed behavior, and the evidence it emits is
signature-, run-, and replay-protected under a documented process boundary. Stronger
independence (host-privileged adversary resistance) and measured detection rates remain
future work. This publication is an evaluated engineering artifact pending independent
technical review; it is not self-approved.

## References

See the linked standards: MITRE ATT&CK T1078, OWASP API Security BOLA, NIST SP 800-115,
and RFC 8032 (Ed25519). Source, tests, the verification record, recorded observations,
and the evidence manifest are linked as artifacts above.
""",
    },
    {
        "pub_id": "QR-RES-001",
        "slug": "configuration-claims-vs-runtime-security",
        "title": "Configuration Claims vs Runtime Security",
        "category": "frameworks", "rtype": "research-publication", "level": "advanced",
        "pub_type": "evaluated-artifact",
        "collection": "A. Adversarial Verification & Evidence Integrity",
        "version": "1.0.0", "maturity": "technical-review",
        "publisher": "Qwalora LLC, Ranger research practice",
        "topic": "Configuration drift, Enforcement, Behavioral testing, Audit",
        "board": 1, "role": "detection-engineer",
        "source_attribution": "Qwalora LLC, Ranger research practice",
        "related": "QR-RES-002,QR-RES-017,QR-RES-028",
        "artifacts": [
            {"label": "Source (target, evaluators)", "url": _REPO + "/QR-RES-001/qr_res_001"},
            {"label": "Test suite", "url": _REPO + "/QR-RES-001/tests"},
            {"label": "Verification record", "url": _RAW + "/QR-RES-001/evidence/verification.json"},
            {"label": "Recorded results", "url": _RAW + "/QR-RES-001/evidence/scenarios.json"},
            {"label": "Evidence manifest (sha256)", "url": _RAW + "/QR-RES-001/evidence/manifest.sha256"},
            {"label": "Reproduction instructions (README)", "url": _RAW + "/QR-RES-001/README.md"},
        ],
        "refs": [
            {"label": "NIST SP 800-53 Rev 5: Security and Privacy Controls",
             "url": "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"},
            {"label": "NIST SP 800-115: Technical Guide to Information Security Testing",
             "url": "https://csrc.nist.gov/pubs/sp/800/115/final"},
            {"label": "OWASP Application Security Verification Standard",
             "url": "https://owasp.org/www-project-application-security-verification-standard/"},
        ],
        "verification": {
            "publication_id": "QR-RES-001", "version": "1.0.0",
            "execution": {"status": "executed", "environment": "Linux / Python 3.13.16 (single cloud container)",
                          "source_commit": "951ad43ce228442ce615ec3edc2d9fd184f0aaf9"},
            "tests": {"total": 11, "passed": 11, "failed": 0, "pytest_exit_code": 0},
            "scenarios": {"count": 6, "gaps_match_expected": 6, "claim_vs_reality_gaps_observed": 7},
            "independent_verification": {"performed": True,
                "verifier": "behavioral evaluator probing the running target (separate process)",
                "method": "a configuration-only evaluator is compared against a behavioral evaluator; "
                          "disagreements are the claim-vs-reality gaps; evidence is Ed25519-signed.",
                "trust_boundary": "process isolation on one host; the behavioral evaluator never reads "
                                  "the declared config. NOT VM/container isolation."},
            "review": {"technical_status": "pending_technical_review", "approved_by": None, "approved_at": None},
        },
        "summary": "A configuration-only evaluator that trusts declared security settings is compared with a "
        "behavioral evaluator that probes what the application actually enforces, across five controls. The "
        "reference run found seven claim-vs-reality gaps across six scenarios: controls declared enforced but "
        "absent at runtime (authentication, debug suppression, security headers, TLS, directory listing) and a "
        "control enforced but undeclared. Declared configuration is shown not to be evidence of enforcement. An "
        "evaluated engineering artifact, pending independent technical review.",
        "body": r"""## Technical abstract

Security reviews routinely read a configuration file or a self-reported settings
endpoint and conclude a control is in place. This study builds two evaluators for
the same five controls, a configuration-only evaluator that trusts the declared
settings and a behavioral evaluator that probes the running application, and
measures how often they disagree. In the reference run the behavioral evaluator
found seven enforcement gaps that the configuration-only evaluator certified as
compliant.

## Engineering objective

Quantify the gap between declared security configuration and runtime enforcement
for a defined control set: auth_required, debug_disabled, security_headers,
tls_enforced, listing_disabled.

## System topology

A target process ships a declared configuration and an actual behavior, chosen per
scenario. The behavioral evaluator reaches it only over loopback HTTP and never
reads the declared config; the configuration-only evaluator reads only the declared
config.

## Environment specifications

Linux, Python 3.11+ (run on 3.13), standard library only, loopback only.

## Exact experiment commands

```
python run_experiment.py     # runs tests + all scenarios, writes evidence/
python -m pytest -v
```

## Scenarios

Six scenarios pair a declared configuration with an actual behavior: all aligned;
auth declared on but off at runtime; debug declared off but a stack trace leaks;
security headers declared but missing; multiple claims unmet (headers, TLS,
listing); and a control enforced but not declared.

## Detection and defensive analysis

Each control is decided from observed behavior: an unauthenticated 200 on a
protected route (auth not enforced), a stack trace in an error body (debug not
suppressed), missing response headers, absent HSTS, or a served directory index.
The configuration-only evaluator reports a control enforced iff the declared value
says so.

## Verification evidence

The orchestrator records the real pytest output, per-scenario config-vs-behavioral
verdicts and the specific gaps, Ed25519-signed evidence records, a sha256 manifest
over artifacts and source, and a machine-readable verification record anchored to
the source commit.

## Measured results (reference run)

- Tests: 11/11 passed, pytest exit 0.
- Scenarios: 6/6 produced exactly the expected gap set.
- Claim-vs-reality gaps observed: 7. Central finding: a control declared enforced
  (auth_required) is observed unenforced at runtime, which the configuration-only
  evaluator does not catch.

## Limitations and threats to validity

Process isolation on one host, not VM/container isolation. Five controls and six
deterministic scenarios; no population-level rate is claimed. Synthetic app and
data only.

## Conclusions

A behavioral evaluator catches enforcement failures that a configuration-only
evaluator certifies as compliant. Declared configuration is not evidence of
enforcement. Pending independent technical review; not self-approved.

## References

NIST SP 800-53 Rev 5, NIST SP 800-115, and the OWASP ASVS are linked as references;
source, tests, the verification record, results, and the manifest are linked as
artifacts above.
""",
    },
    {
        "pub_id": "QR-RES-003",
        "slug": "signed-evidence-replay-and-freshness",
        "title": "Signed Evidence Replay and Freshness",
        "category": "frameworks", "rtype": "research-publication", "level": "research",
        "pub_type": "evaluated-artifact",
        "collection": "A. Adversarial Verification & Evidence Integrity",
        "version": "1.0.0", "maturity": "technical-review",
        "publisher": "Qwalora LLC, Ranger research practice",
        "topic": "Evidence integrity, Replay, Freshness, Cryptography",
        "board": 4, "role": "incident-responder",
        "source_attribution": "Qwalora LLC, Ranger research practice",
        "related": "QR-RES-002,QR-RES-025,QR-RES-029",
        "artifacts": [
            {"label": "Source (envelope, verifier)", "url": _REPO + "/QR-RES-003/qr_res_003"},
            {"label": "Test suite", "url": _REPO + "/QR-RES-003/tests"},
            {"label": "Verification record", "url": _RAW + "/QR-RES-003/evidence/verification.json"},
            {"label": "Recorded cases", "url": _RAW + "/QR-RES-003/evidence/cases.json"},
            {"label": "Evidence manifest (sha256)", "url": _RAW + "/QR-RES-003/evidence/manifest.sha256"},
            {"label": "Reproduction instructions (README)", "url": _RAW + "/QR-RES-003/README.md"},
        ],
        "refs": [
            {"label": "RFC 8032: Edwards-Curve Digital Signature Algorithm (Ed25519)",
             "url": "https://www.rfc-editor.org/rfc/rfc8032"},
            {"label": "NIST SP 800-57: Recommendation for Key Management",
             "url": "https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final"},
        ],
        "verification": {
            "publication_id": "QR-RES-003", "version": "1.0.0",
            "execution": {"status": "executed", "environment": "Linux / Python 3.13.16 (single cloud container)",
                          "source_commit": "951ad43ce228442ce615ec3edc2d9fd184f0aaf9"},
            "tests": {"total": 12, "passed": 12, "failed": 0, "pytest_exit_code": 0},
            "scenarios": {"count": 8, "verdict_matches_expected": 8,
                          "verdict_tally": {"ACCEPT": 1, "REJECT": 6, "INCONCLUSIVE": 1}},
            "independent_verification": {"performed": True,
                "verifier": "challenge-issuing verifier with its own key and replay/freshness state",
                "method": "a one-time challenge binds an envelope to one assessment; acceptance requires "
                          "signature, challenge binding, freshness window, envelope-id uniqueness, and manifest "
                          "hashes; adversarial envelopes are rejected.",
                "trust_boundary": "the verifier's key and challenge/replay state are its own; a protocol study, "
                                  "not a claim of host or network isolation."},
            "review": {"technical_status": "pending_technical_review", "approved_by": None, "approved_at": None},
        },
        "summary": "Challenge-bound evidence envelopes with freshness windows, replay tracking, and "
        "artifact-manifest integrity. A one-time verifier challenge binds each envelope to a single assessment; "
        "acceptance requires a valid signature, the right challenge, a live freshness window, a unique envelope "
        "id, and matching artifact hashes. The reference run accepted valid fresh evidence and rejected stale, "
        "replayed, substituted-challenge, manipulated-manifest, tampered, and foreign-key envelopes (12/12 tests, "
        "8/8 cases). An evaluated engineering artifact, pending independent technical review.",
        "body": r"""## Technical abstract

Signed evidence is only trustworthy if it is bound to the assessment that produced
it and cannot be reused. This study builds a challenge-bound, time-boxed evidence
envelope and a verifier that defeats replay, cross-assessment submission, stale
evidence, and post-signing manifest tampering. The reference run accepted valid
fresh evidence and rejected every adversarial envelope.

## Engineering objective

Guarantee that an evidence envelope is fresh, bound to one verifier-issued
challenge, used at most once, and faithful to the artifacts it attests to.

## Design

An envelope binds, under an Ed25519 signature: a one-time `challenge` the verifier
issued; an `issued_at`/`expires_at` freshness window; a unique `envelope_id`; and a
`manifest` of sha256 hashes of the attested artifacts. The verifier issues the
challenge, then accepts only if signature, challenge binding, freshness, envelope-id
uniqueness, and every artifact hash hold.

## Environment specifications

Linux, Python 3.11+ (run on 3.13), `cryptography` + `pytest`, no network. A pure
protocol study.

## Exact experiment commands

```
python run_experiment.py
python -m pytest -v
```

## Adversarial cases

Valid fresh evidence; stale evidence past its window; replayed evidence; a
substituted/unknown challenge; a manipulated manifest (an artifact changed after
signing); a tampered envelope field; a foreign signing key; and an attested
artifact not supplied.

## Verification evidence

The orchestrator records the real pytest output, per-case verdicts and the specific
rejection reason, signed case records, a sha256 manifest, and a verification record
anchored to the source commit.

## Measured results (reference run)

- Tests: 12/12 passed, pytest exit 0.
- Cases: 8/8 verdicts match expected (ACCEPT 1, REJECT 6, INCONCLUSIVE 1).
- Rejection reasons recorded: stale-expired, challenge-already-used (replay),
  unknown-or-substituted-challenge, manifest-hash-mismatch, bad-signature, and
  foreign-signing-key. A missing attested artifact is INCONCLUSIVE, never accepted.

## Limitations and threats to validity

A protocol study, not host or network isolation. Freshness uses the verifier's
clock; clock skew across parties is out of scope for v1.0.0. The one-time challenge
is the primary replay defense, with the envelope-id guard as a secondary control.
Synthetic artifacts only.

## Conclusions

Challenge binding, a freshness window, replay tracking, and manifest hashing
together reject stale, replayed, substituted, manipulated, tampered, and
foreign-key evidence while accepting valid fresh evidence. Pending independent
technical review; not self-approved.

## References

RFC 8032 (Ed25519) and NIST SP 800-57 are linked as references; source, tests, the
verification record, cases, and the manifest are linked as artifacts above.
""",
    },
    {
        "pub_id": "QR-RES-017",
        "slug": "broken-object-level-authorization",
        "title": "Broken Object-Level Authorization",
        "category": "offensive", "rtype": "research-publication", "level": "advanced",
        "pub_type": "evaluated-artifact",
        "collection": "D. Vulnerability & Application Security Research",
        "version": "1.0.0", "maturity": "technical-review",
        "publisher": "Qwalora LLC, Ranger research practice",
        "topic": "BOLA, Authorization, API security, OWASP",
        "board": 3, "role": "detection-engineer",
        "source_attribution": "Qwalora LLC, Ranger research practice",
        "related": "QR-RES-002,QR-RES-001,QR-RES-009",
        "artifacts": [
            {"label": "Source (API, BOLA probe)", "url": _REPO + "/QR-RES-017/qr_res_017"},
            {"label": "Test suite", "url": _REPO + "/QR-RES-017/tests"},
            {"label": "Verification record", "url": _RAW + "/QR-RES-017/evidence/verification.json"},
            {"label": "Recorded results", "url": _RAW + "/QR-RES-017/evidence/scenarios.json"},
            {"label": "Evidence manifest (sha256)", "url": _RAW + "/QR-RES-017/evidence/manifest.sha256"},
            {"label": "Reproduction instructions (README)", "url": _RAW + "/QR-RES-017/README.md"},
        ],
        "refs": [
            {"label": "OWASP API Security Top 10: Broken Object Level Authorization",
             "url": "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"},
            {"label": "OWASP Web Security Testing Guide: Authorization Testing",
             "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        ],
        "verification": {
            "publication_id": "QR-RES-017", "version": "1.0.0",
            "execution": {"status": "executed", "environment": "Linux / Python 3.13.16 (single cloud container)",
                          "source_commit": "951ad43ce228442ce615ec3edc2d9fd184f0aaf9"},
            "tests": {"total": 3, "passed": 3, "failed": 0, "pytest_exit_code": 0},
            "scenarios": {"count": 2, "assessments_match_intent": 2,
                          "bola_detected_in_vulnerable": True, "fixed_build_authorization_correct": True},
            "independent_verification": {"performed": True,
                "verifier": "object-level authorization probe against the running API (separate process)",
                "method": "positive and negative object-level access cases with two synthetic identities run "
                          "against a vulnerable and a fixed build; a cross-user disclosure is the BOLA finding; "
                          "evidence is Ed25519-signed.",
                "trust_boundary": "process isolation on one host; the probe uses only scoped HTTP tokens. NOT "
                                  "VM/container isolation."},
            "review": {"technical_status": "pending_technical_review", "approved_by": None, "approved_at": None},
        },
        "summary": "A disposable multiuser records API in a vulnerable and a fixed build, with an automated probe "
        "that runs positive and negative object-level access cases with two synthetic identities. The vulnerable "
        "build discloses another user's record by id (broken object-level authorization); the fixed build allows "
        "owner access and denies cross-user and anonymous access. The probe catches the flaw in the vulnerable "
        "build and confirms its absence in the fixed build (3/3 tests). An evaluated engineering artifact, pending "
        "independent technical review.",
        "body": r"""## Technical abstract

Broken object-level authorization (BOLA) is the most common serious API flaw: an
endpoint authenticates the caller but does not check that the caller owns the object
requested, so any authenticated user can read another user's records by changing an
id. This study builds the flaw and its fix and an automated probe that reliably
distinguishes them.

## Threat model

An authenticated but non-owning user attempts to read another user's object by id,
and to enumerate ids. Mapping: OWASP API Security Top 10 "Broken Object Level
Authorization".

## System topology

A records API serves two synthetic users' records. In the vulnerable build the
handler omits the ownership check; in the fixed build it enforces it. The probe
reaches the API only over loopback HTTP with scoped bearer tokens.

## Environment specifications

Linux, Python 3.11+ (run on 3.13), standard library only, loopback only.

## Exact experiment commands

```
python run_experiment.py     # runs tests + both builds, writes evidence/
python -m pytest -v
```

## Adversarial and positive cases

Owner reads own record (must be allowed); one user reads another's record (must be
denied); anonymous access (must be denied); and an id-enumeration walk counting
records disclosed to a user who does not own them.

## Defensive implementation

The fix enforces an object-level ownership check: a record is returned only when its
owner matches the authenticated caller, else 403; unauthenticated callers get 401.

## Verification evidence

The orchestrator records the real pytest output, per-build findings (owner access,
cross-user leak, anonymous denial, enumerated foreign records), signed evidence, a
sha256 manifest, and a verification record anchored to the source commit.

## Measured results (reference run)

- Tests: 3/3 passed, pytest exit 0; assessments match intent 2/2.
- Vulnerable build: cross-user disclosure observed (one user reads another's record;
  the record is enumerable). BOLA present.
- Fixed build: owner access works, cross-user denied (403), anonymous denied (401),
  no foreign record enumerable. Authorization correct.

## Limitations and threats to validity

Process isolation on one host, not VM/container isolation. Two users and three
records; no population-level rate claimed. Object-level read authorization only;
write/delete and nested-object authorization are out of scope for v1.0.0.

## Conclusions

An automated probe catches a cross-user object disclosure in the vulnerable build
and confirms its absence in the fixed build, with signed evidence. Pending
independent technical review; not self-approved.

## References

The OWASP API Security BOLA entry and the OWASP WSTG are linked as references;
source, tests, the verification record, results, and the manifest are linked as
artifacts above.
""",
    },
]



# Collection 2: Ranger Cohort Readiness & Technical Knowledge publications.
import catalog_kb as _catalog_kb  # noqa: E402
PUBLICATIONS = PUBLICATIONS + _catalog_kb.PUBLICATIONS
